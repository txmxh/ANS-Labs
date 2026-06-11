"""
 Copyright (c) 2025 Computer Networks Group @ UPB

 Permission is hereby granted, free of charge, to any person obtaining a copy of
 this software and associated documentation files (the "Software"), to deal in
 the Software without restriction, including without limitation the rights to
 use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 the Software, and to permit persons to whom the Software is furnished to do so,
 subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 """

#!/usr/bin/env python3

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, arp
from ryu.topology import event
from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase
import topo


class SPRouter(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SPRouter, self).__init__(*args, **kwargs)

        self.topo_net = topo.Fattree(4)
        self.datapaths = {}

        # adjacency[dpid_a][dpid_b] = port on dpid_a that leads to dpid_b
        self.adjacency = {}

        # host_to_edge[host_ip] = (edge_switch_dpid, port_on_edge_switch)
        # Populated from topo at build time — no runtime ARP learning needed for ports
        self.host_to_edge = {}

        self.arp_table = {}   # ip → mac, learned at runtime
        self.topo_ready = False

    # ---- TOPOLOGY DISCOVERY (Ryu API, kept for logging) ----
    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        switch_list = get_switch(self, None)
        link_list   = get_link(self, None)
        self.logger.info("Topology event: %d switches, %d links",
                         len(switch_list), len(link_list))

    # ---- SWITCH CONNECTS ----
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser

        self.datapaths[datapath.id] = datapath

        # Default table-miss rule: send unknown packets to controller
        match   = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        # Once all 20 switches have connected, build full adjacency + install all routes
        if len(self.datapaths) == 20 and not self.topo_ready:
            self.logger.info("All 20 switches connected — building topology.")
            self.build_adjacency_from_topo()
            self.install_all_routes()

    # ---- BUILD ADJACENCY + HOST PORT MAP FROM TOPO OBJECT ----
    def build_adjacency_from_topo(self):
        """
        Reconstruct exact Mininet port numbers by replaying the same addLink
        iteration order used in fat-tree.py.

        fat-tree.py iterates: all_nodes = switches + servers, processes each
        Edge object once (via id(edge) dedup), and calls addLink(lnode, rnode).
        Mininet assigns ports left-to-right starting at 1 for each node.

        We do the same iteration here to assign matching port numbers.
        Two separate passes keep the logic clean:
          Pass 1 — switch↔switch links  → fills self.adjacency
          Pass 2 — edge↔host links      → fills self.host_to_edge
        Both passes must use the SAME port counter so port assignments match
        exactly what Mininet did.
        """
        # Map Python object id of each topo Node → its Mininet dpid
        # switches[0] → s1 → dpid 1, switches[1] → s2 → dpid 2, …
        node_to_dpid = {id(sw): i + 1
                        for i, sw in enumerate(self.topo_net.switches)}

        num_sw = len(self.topo_net.switches)

        # One port counter per switch (starts at 1, increments with every link)
        port_counter = {i + 1: 1 for i in range(num_sw)}

        self.adjacency   = {i + 1: {} for i in range(num_sw)}
        self.host_to_edge = {}

        all_nodes   = self.topo_net.switches + self.topo_net.servers
        added_edges = set()

        for node in all_nodes:
            for edge in node.edges:
                if id(edge) in added_edges:
                    continue
                added_edges.add(id(edge))

                lnode = edge.lnode
                rnode = edge.rnode
                l_is_sw = (lnode.type != 'server')
                r_is_sw = (rnode.type != 'server')

                # Allocate the next port on lnode (if it is a switch)
                l_port = None
                if l_is_sw:
                    l_dpid = node_to_dpid[id(lnode)]
                    l_port = port_counter[l_dpid]
                    port_counter[l_dpid] += 1

                # Allocate the next port on rnode (if it is a switch)
                r_port = None
                if r_is_sw:
                    r_dpid = node_to_dpid[id(rnode)]
                    r_port = port_counter[r_dpid]
                    port_counter[r_dpid] += 1

                if l_is_sw and r_is_sw:
                    # Switch ↔ Switch link — store both directions
                    self.adjacency[l_dpid][r_dpid] = l_port
                    self.adjacency[r_dpid][l_dpid] = r_port

                elif l_is_sw and not r_is_sw:
                    # Edge switch ↔ Host (lnode=edge switch, rnode=server)
                    self.host_to_edge[rnode.ip] = (l_dpid, l_port)

                elif r_is_sw and not l_is_sw:
                    # Host ↔ Edge switch (lnode=server, rnode=edge switch)
                    self.host_to_edge[lnode.ip] = (r_dpid, r_port)

        self.topo_ready = True
        self.logger.info(
            "Adjacency ready: %d switches, %d inter-switch links, %d hosts mapped",
            len(self.adjacency),
            sum(len(v) for v in self.adjacency.values()) // 2,
            len(self.host_to_edge)
        )

    # ---- INSTALL ROUTES FOR ALL HOSTS AT ONCE ----
    def install_all_routes(self):
        """
        After topology is built, install IP forwarding rules on every switch
        for every known host. This avoids relying on runtime ARP to trigger
        route installation.
        """
        for host_ip, (edge_dpid, host_port) in self.host_to_edge.items():
            self.install_host_routes(host_ip, edge_dpid, host_port)
        self.logger.info("All routes installed for %d hosts.", len(self.host_to_edge))

    # ---- ADD FLOW RULE ----
    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod  = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                  match=match, instructions=inst)
        datapath.send_msg(mod)

    # ---- DIJKSTRA ----
    def dijkstra(self, src_dpid):
        """
        Standard Dijkstra on the switch-only graph (all edge weights = 1).
        Returns {dst_dpid: next_hop_dpid} — the first hop from src toward dst.
        """
        dist = {dpid: float('inf') for dpid in self.adjacency}
        prev = {dpid: None         for dpid in self.adjacency}
        dist[src_dpid] = 0
        unvisited = set(self.adjacency.keys())

        while unvisited:
            # Pick the unvisited node with smallest tentative distance
            u = min(unvisited, key=lambda x: dist[x])
            if dist[u] == float('inf'):
                break   # remaining nodes are unreachable
            unvisited.remove(u)

            for neighbor in self.adjacency[u]:
                if neighbor not in unvisited:
                    continue
                new_dist = dist[u] + 1
                if new_dist < dist[neighbor]:
                    dist[neighbor] = new_dist
                    prev[neighbor] = u

        # Reconstruct next-hop for every reachable destination
        next_hop = {}
        for dst in self.adjacency:
            if dst == src_dpid:
                continue
            # Walk prev[] chain from dst back to src
            curr = dst
            while prev[curr] is not None and prev[curr] != src_dpid:
                curr = prev[curr]
            if prev[curr] == src_dpid:
                next_hop[dst] = curr   # first hop after src

        return next_hop

    # ---- INSTALL ROUTES FOR ONE HOST ----
    def install_host_routes(self, host_ip, edge_dpid, host_port):
        """
        Push one IP-destination flow rule per switch for host_ip.
        Every switch gets: match(ipv4_dst=host_ip) → output(correct_port).
        """
        for dpid, datapath in self.datapaths.items():
            parser = datapath.ofproto_parser

            if dpid == edge_dpid:
                # This switch is directly attached to the host
                out_port = host_port
            else:
                # Use Dijkstra to find the next hop toward edge_dpid
                next_hops = self.dijkstra(dpid)
                if edge_dpid not in next_hops:
                    self.logger.warning("No path from switch %d to %d", dpid, edge_dpid)
                    continue
                next_dpid = next_hops[edge_dpid]
                out_port  = self.adjacency[dpid][next_dpid]

            match   = parser.OFPMatch(eth_type=0x0800, ipv4_dst=host_ip)
            actions = [parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, 1, match, actions)

    # ---- PACKET IN HANDLER ----
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg      = ev.msg
        datapath = msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser
        in_port  = msg.match['in_port']

        pkt     = packet.Packet(msg.data)
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt  = pkt.get_protocol(ipv4.ipv4)

        if arp_pkt:
            self.handle_arp(datapath, in_port, arp_pkt, msg)
        elif ip_pkt:
            # IP packets should already be handled by flow rules.
            # If one reaches the controller, drop it (avoids flooding loops).
            pass

    # ---- ARP HANDLER ----
    def handle_arp(self, datapath, in_port, arp_pkt, msg):
        """
        Learn src MAC for future ARP replies, then flood the ARP so hosts
        can resolve each other's MAC addresses.
        ARP replies are also flooded — the destination host will accept its own.
        """
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser

        src_ip  = arp_pkt.src_ip
        src_mac = arp_pkt.src_mac
        dst_ip  = arp_pkt.dst_ip

        # Learn MAC address
        self.arp_table[src_ip] = src_mac

        # If we know the destination MAC, send a unicast ARP reply directly
        # back to the requester (avoids unnecessary flooding for ARP requests)
        if arp_pkt.opcode == arp.ARP_REQUEST and dst_ip in self.arp_table:
            dst_mac = self.arp_table[dst_ip]
            # Build ARP reply
            e = ethernet.ethernet(dst=src_mac, src=dst_mac,
                                  ethertype=0x0806)
            a = arp.arp(opcode=arp.ARP_REPLY,
                        src_mac=dst_mac, src_ip=dst_ip,
                        dst_mac=src_mac, dst_ip=src_ip)
            reply_pkt = packet.Packet()
            reply_pkt.add_protocol(e)
            reply_pkt.add_protocol(a)
            reply_pkt.serialize()

            actions = [parser.OFPActionOutput(in_port)]
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=ofproto.OFP_NO_BUFFER,
                in_port=ofproto.OFPP_CONTROLLER,
                actions=actions,
                data=reply_pkt.data
            )
            datapath.send_msg(out)
            return

        # Otherwise flood the ARP (request or reply we can't answer yet)
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        )
        datapath.send_msg(out)
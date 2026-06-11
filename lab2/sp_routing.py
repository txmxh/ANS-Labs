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
        self.adjacency = {}
        self.host_locations = {}
        self.arp_table = {}
        self.topo_ready = False

    # ---- TOPOLOGY DISCOVERY (kept as fallback) ----
    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        switch_list = get_switch(self, None)
        link_list   = get_link(self, None)
        self.logger.info("Topology updated: %d switches, %d links",
                         len(switch_list), len(link_list))

    # ---- SWITCH CONNECTS ----
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser

        self.datapaths[datapath.id] = datapath

        # Default rule: unknown packets go to controller
        match   = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        # When all 20 switches connected, build adjacency from topo
        if len(self.datapaths) == 20 and not self.topo_ready:
            self.logger.info("All switches connected! Building adjacency from topo.")
            self.build_adjacency_from_topo()

    # ---- BUILD ADJACENCY DIRECTLY FROM TOPO OBJECT ----
    def build_adjacency_from_topo(self):
        """
        Build adjacency map by simulating the same addLink order as fat-tree.py.
        This gives us exact port numbers without relying on Ryu's get_link().

        Logic: fat-tree.py calls addLink(lnode, rnode) in the same order we iterate
        here. Each call assigns the next available port on each node.
        """
        # Map topo Node id → dpid (switches[i] has name s{i+1} → dpid=i+1)
        node_to_dpid = {}
        for i, sw in enumerate(self.topo_net.switches):
            node_to_dpid[id(sw)] = i + 1

        # Port counter: next available port for each switch dpid
        num_sw = len(self.topo_net.switches)
        port_counter = {i+1: 1 for i in range(num_sw)}

        # Initialize empty adjacency
        self.adjacency = {i+1: {} for i in range(num_sw)}

        # Simulate addLink calls in same order as fat-tree.py:
        # iterate all_nodes = switches + servers, process each edge once
        all_nodes = self.topo_net.switches + self.topo_net.servers
        added_edges = set()

        for node in all_nodes:
            for edge in node.edges:
                if id(edge) not in added_edges:
                    added_edges.add(id(edge))
                    lnode = edge.lnode
                    rnode = edge.rnode

                    l_is_switch = (lnode.type != 'server')
                    r_is_switch = (rnode.type != 'server')

                    l_port = None
                    r_port = None

                    # Assign next port to lnode if it's a switch
                    if l_is_switch:
                        l_dpid = node_to_dpid[id(lnode)]
                        l_port = port_counter[l_dpid]
                        port_counter[l_dpid] += 1

                    # Assign next port to rnode if it's a switch
                    if r_is_switch:
                        r_dpid = node_to_dpid[id(rnode)]
                        r_port = port_counter[r_dpid]
                        port_counter[r_dpid] += 1

                    # Store in adjacency only for switch-to-switch links
                    if l_is_switch and r_is_switch:
                        self.adjacency[l_dpid][r_dpid] = l_port
                        self.adjacency[r_dpid][l_dpid] = r_port

        self.topo_ready = True
        self.logger.info("Adjacency built! %d switches, %d total links",
                         len(self.adjacency),
                         sum(len(v) for v in self.adjacency.values()))

        # Install routes for hosts already discovered before topo was ready
        for host_ip, (edge_dpid, host_port) in self.host_locations.items():
            self.install_host_routes(host_ip, edge_dpid, host_port)

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
        Run Dijkstra from src_dpid.
        Returns {dst_dpid: next_hop_dpid}
        """
        dist = {dpid: float('inf') for dpid in self.adjacency}
        prev = {dpid: None for dpid in self.adjacency}
        dist[src_dpid] = 0
        unvisited = set(self.adjacency.keys())

        while unvisited:
            u = min(unvisited, key=lambda x: dist[x])
            if dist[u] == float('inf'):
                break
            unvisited.remove(u)

            for neighbor in self.adjacency[u]:
                if neighbor in unvisited:
                    new_dist = dist[u] + 1
                    if new_dist < dist[neighbor]:
                        dist[neighbor] = new_dist
                        prev[neighbor] = u

        # Build next_hop by tracing paths back
        next_hop = {}
        for dst in self.adjacency:
            if dst == src_dpid:
                continue
            path = []
            curr = dst
            while prev[curr] is not None:
                path.append(curr)
                curr = prev[curr]
            if curr == src_dpid:
                path.append(src_dpid)
                path.reverse()
                if len(path) >= 2:
                    next_hop[dst] = path[1]

        return next_hop

    # ---- INSTALL ROUTES FOR A HOST ----
    def install_host_routes(self, host_ip, edge_dpid, host_port):
        """Install flow rules on ALL switches to reach host_ip"""
        if not self.topo_ready:
            self.logger.info("Topo not ready, route for %s will install later",
                             host_ip)
            return

        for dpid, datapath in self.datapaths.items():
            parser = datapath.ofproto_parser

            if dpid == edge_dpid:
                # Directly connected to host
                match   = parser.OFPMatch(eth_type=0x0800, ipv4_dst=host_ip)
                actions = [parser.OFPActionOutput(host_port)]
                self.add_flow(datapath, 1, match, actions)
                self.logger.info("Switch %s: %s → port %s (direct)",
                                 dpid, host_ip, host_port)
            else:
                # Find next hop via shortest path
                next_hops = self.dijkstra(dpid)
                if edge_dpid in next_hops:
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
        dpid     = datapath.id
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser
        in_port  = msg.match['in_port']

        pkt = packet.Packet(msg.data)

        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            self.handle_arp(datapath, in_port, arp_pkt, msg)
            return

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            self.handle_ip(datapath, in_port, ip_pkt, msg)

    def handle_arp(self, datapath, in_port, arp_pkt, msg):
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
        src_ip  = arp_pkt.src_ip
        src_mac = arp_pkt.src_mac

        self.arp_table[src_ip] = src_mac

        # Only learn if it's a known server IP
        server_ips = {s.ip for s in self.topo_net.servers}

        if src_ip in server_ips and src_ip not in self.host_locations:
            self.host_locations[src_ip] = (datapath.id, in_port)
            self.logger.info("Discovered host %s at switch %s port %s",
                             src_ip, datapath.id, in_port)
            self.install_host_routes(src_ip, datapath.id, in_port)

        # Flood ARP
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        )
        datapath.send_msg(out)

    def handle_ip(self, datapath, in_port, ip_pkt, msg):
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        )
        datapath.send_msg(out)
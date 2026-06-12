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
from ryu.lib import hub
import topo


class SPRouter(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SPRouter, self).__init__(*args, **kwargs)

        self.k = 4
        self.topo_net = topo.Fattree(self.k)
        self.datapaths = {}

        # adjacency[dpid_a][dpid_b] = port on dpid_a leading to dpid_b
        # Built from Ryu get_link() — satisfies the lab requirement of no
        # static switch-to-switch port assumptions.
        self.adjacency = {}

        # host_to_edge[host_ip] = (edge_switch_dpid, port_on_edge_switch)
        # get_link() never reports host ports (hosts don't speak OpenFlow),
        # so we derive these by replaying the same edge-iteration order that
        # fat-tree.py uses when calling addLink().  The port assignments are
        # therefore deterministic and correct without any static hardcoding.
        self.host_to_edge = {}

        # ip → mac, learned at runtime from ARP source fields
        self.arp_table = {}

        # Guard so we only trigger the build once
        self.topo_ready = False

        # k=4 → 4 core + 8 agg + 8 edge = 20 switches
        self.total_switches = (self.k // 2) ** 2 + self.k * self.k

    # -----------------------------------------------------------------------
    # EventSwitchEnter — only used for informational logging here.
    # Route installation is driven by OFPSwitchFeatures so we have datapaths.
    # -----------------------------------------------------------------------
    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        switch_list = get_switch(self, None)
        self.logger.info("EventSwitchEnter: %d / %d switches registered",
                         len(switch_list), self.total_switches)

    # -----------------------------------------------------------------------
    # OFPSwitchFeatures — fires when each switch's OpenFlow session opens.
    # Once all switches have connected we spawn a background thread that
    # waits for LLDP to settle and then builds topology + installs routes.
    # -----------------------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser

        self.datapaths[datapath.id] = datapath

        # Default table-miss: send unknown packets to controller
        match   = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        self.logger.info("Switch %d connected (%d / %d)",
                         datapath.id, len(self.datapaths), self.total_switches)

        # When the last switch connects, kick off the build in a background
        # thread so we can sleep without blocking the Ryu event loop.
        if len(self.datapaths) == self.total_switches and not self.topo_ready:
            self.topo_ready = True   # prevent a second spawn on a re-connect
            hub.spawn(self._build_and_install)

    # -----------------------------------------------------------------------
    # Background thread: sleep → get_link() → host ports → install all routes.
    #
    # The sleep is essential: Ryu's LLDP-based link discovery runs in its own
    # event loop.  OFPSwitchFeatures fires as soon as the OpenFlow session
    # opens, which is BEFORE LLDP has exchanged packets on every link.
    # Calling get_link() immediately would return an empty (or partial) list,
    # leaving self.adjacency empty and breaking all cross-switch routing.
    # Two seconds is conservative but safe for a 20-switch topology.
    # -----------------------------------------------------------------------
    def _build_and_install(self):
        self.logger.info("Waiting 2 s for LLDP link discovery to complete...")
        hub.sleep(2)

        self.build_adjacency_from_ryu()   # switch↔switch ports via get_link()
        self.build_host_ports_from_topo() # host↔edge ports via topo replay
        self.install_all_routes()

    # -----------------------------------------------------------------------
    # BUILD SWITCH ADJACENCY using Ryu get_link().
    # get_link() returns every directed link (A→B and B→A) with the real
    # port number on the source switch.  We store both directions so that
    # Dijkstra can look up the egress port on any switch toward any neighbour.
    # -----------------------------------------------------------------------
    def build_adjacency_from_ryu(self):
        link_list = get_link(self, None)
        self.adjacency = {}

        for link in link_list:
            src  = link.src.dpid
            dst  = link.dst.dpid
            port = link.src.port_no
            self.adjacency.setdefault(src, {})[dst] = port

        self.logger.info(
            "Adjacency built via get_link(): %d switches, %d directed links",
            len(self.adjacency),
            sum(len(v) for v in self.adjacency.values()),
        )

    # -----------------------------------------------------------------------
    # DISCOVER HOST PORTS by replaying fat-tree.py's addLink() iteration.
    #
    # fat-tree.py iterates all_nodes = switches + servers and deduplicates
    # edges by id(edge).  Mininet assigns port numbers left-to-right starting
    # at 1 for each node in exactly this order.  We replicate the same walk
    # here to recover the port each edge switch uses to reach each host.
    #
    # Why not use get_link()?  Because hosts are not OpenFlow switches —
    # they don't speak LLDP, so Ryu's topology module never sees host links.
    # -----------------------------------------------------------------------
    def build_host_ports_from_topo(self):
        node_to_dpid = {id(sw): i + 1
                        for i, sw in enumerate(self.topo_net.switches)}
        num_sw       = len(self.topo_net.switches)
        port_counter = {i + 1: 1 for i in range(num_sw)}

        all_nodes   = self.topo_net.switches + self.topo_net.servers
        added_edges = set()

        for node in all_nodes:
            for edge in node.edges:
                if id(edge) in added_edges:
                    continue
                added_edges.add(id(edge))

                lnode    = edge.lnode
                rnode    = edge.rnode
                l_is_sw  = (lnode.type != 'server')
                r_is_sw  = (rnode.type != 'server')

                l_port = None
                if l_is_sw:
                    l_dpid = node_to_dpid[id(lnode)]
                    l_port = port_counter[l_dpid]
                    port_counter[l_dpid] += 1

                r_port = None
                if r_is_sw:
                    r_dpid = node_to_dpid[id(rnode)]
                    r_port = port_counter[r_dpid]
                    port_counter[r_dpid] += 1

                # Record only host-facing edges
                if l_is_sw and not r_is_sw:
                    self.host_to_edge[rnode.ip] = (l_dpid, l_port)
                elif r_is_sw and not l_is_sw:
                    self.host_to_edge[lnode.ip] = (r_dpid, r_port)

        self.logger.info("Host ports derived from topo: %d hosts mapped",
                         len(self.host_to_edge))

    # -----------------------------------------------------------------------
    # INSTALL ROUTES FOR ALL HOSTS proactively.
    # -----------------------------------------------------------------------
    def install_all_routes(self):
        for host_ip, (edge_dpid, host_port) in self.host_to_edge.items():
            self.install_host_routes(host_ip, edge_dpid, host_port)
        self.logger.info("All routes installed for %d hosts.", len(self.host_to_edge))

    # -----------------------------------------------------------------------
    # INSTALL ROUTES FOR ONE HOST across every switch in the fabric.
    # -----------------------------------------------------------------------
    def install_host_routes(self, host_ip, edge_dpid, host_port):
        for dpid, datapath in self.datapaths.items():
            parser = datapath.ofproto_parser

            if dpid == edge_dpid:
                out_port = host_port
            else:
                if dpid not in self.adjacency:
                    self.logger.warning("dpid %d not in adjacency — skipping", dpid)
                    continue
                next_hops = self.dijkstra(dpid)
                if edge_dpid not in next_hops:
                    self.logger.warning("No path: sw %d → sw %d", dpid, edge_dpid)
                    continue
                out_port = self.adjacency[dpid][next_hops[edge_dpid]]

            actions = [parser.OFPActionOutput(out_port)]

            match_ip  = parser.OFPMatch(eth_type=0x0800, ipv4_dst=host_ip)
            match_arp = parser.OFPMatch(eth_type=0x0806, arp_tpa=host_ip)
            self.add_flow(datapath, 1, match_ip,  actions)
            self.add_flow(datapath, 1, match_arp, actions)

    # -----------------------------------------------------------------------
    # ADD FLOW RULE
    # -----------------------------------------------------------------------
    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod  = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                  match=match, instructions=inst)
        datapath.send_msg(mod)

    # -----------------------------------------------------------------------
    # DIJKSTRA — standard single-source shortest path on the switch graph.
    # Returns {dst_dpid: next_hop_dpid} representing the first hop from
    # src_dpid toward every reachable destination switch.
    # -----------------------------------------------------------------------
    def dijkstra(self, src_dpid):
        dist = {dpid: float('inf') for dpid in self.adjacency}
        prev = {dpid: None         for dpid in self.adjacency}
        dist[src_dpid] = 0
        unvisited = set(self.adjacency.keys())

        while unvisited:
            u = min(unvisited, key=lambda x: dist[x])
            if dist[u] == float('inf'):
                break
            unvisited.remove(u)

            for neighbor in self.adjacency[u]:
                if neighbor not in unvisited:
                    continue
                new_dist = dist[u] + 1
                if new_dist < dist[neighbor]:
                    dist[neighbor] = new_dist
                    prev[neighbor] = u

        next_hop = {}
        for dst in self.adjacency:
            if dst == src_dpid:
                continue
            curr = dst
            while prev[curr] is not None and prev[curr] != src_dpid:
                curr = prev[curr]
            if prev[curr] == src_dpid:
                next_hop[dst] = curr

        return next_hop

    # -----------------------------------------------------------------------
    # PACKET IN — only ARP packets should reach the controller once routes
    # are installed (IP is handled fully in hardware by the flow rules).
    # -----------------------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg      = ev.msg
        datapath = msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser
        in_port  = msg.match['in_port']

        pkt     = packet.Packet(msg.data)
        arp_pkt = pkt.get_protocol(arp.arp)

        if arp_pkt:
            self.handle_arp(datapath, in_port, arp_pkt, msg)
        # IP packets hitting the controller mean routes aren't ready yet — drop.

    # -----------------------------------------------------------------------
    # ARP HANDLER
    # Once routes are installed, switches forward ARP directly via the
    # arp_tpa flow rules — so only ARPs sent before the 2-second build window
    # closes will reach the controller.  We flood those to prevent black holes
    # during startup, and we learn MACs to answer future ARP requests.
    # -----------------------------------------------------------------------
    def handle_arp(self, datapath, in_port, arp_pkt, msg):
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser

        src_ip  = arp_pkt.src_ip
        src_mac = arp_pkt.src_mac
        dst_ip  = arp_pkt.dst_ip

        # Learn MAC mapping
        self.arp_table[src_ip] = src_mac

        # Unicast ARP reply if we already know the target's MAC
        if arp_pkt.opcode == arp.ARP_REQUEST and dst_ip in self.arp_table:
            dst_mac = self.arp_table[dst_ip]

            e = ethernet.ethernet(dst=src_mac, src=dst_mac, ethertype=0x0806)
            a = arp.arp(opcode=arp.ARP_REPLY,
                        src_mac=dst_mac, src_ip=dst_ip,
                        dst_mac=src_mac, dst_ip=src_ip)
            reply_pkt = packet.Packet()
            reply_pkt.add_protocol(e)
            reply_pkt.add_protocol(a)
            reply_pkt.serialize()

            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=ofproto.OFP_NO_BUFFER,
                in_port=ofproto.OFPP_CONTROLLER,
                actions=[parser.OFPActionOutput(in_port)],
                data=reply_pkt.data
            )
            datapath.send_msg(out)
            return

        # Flood — ARP request for unknown MAC, or an ARP reply in transit
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=[parser.OFPActionOutput(ofproto.OFPP_FLOOD)],
            data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        )
        datapath.send_msg(out)
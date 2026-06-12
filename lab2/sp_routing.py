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

        self.k = 4
        self.topo_net = topo.Fattree(self.k)
        self.datapaths = {}

        # adjacency[dpid_a][dpid_b] = port on dpid_a leading to dpid_b
        # Built from Ryu get_link() — no static port assumptions.
        self.adjacency = {}

        # host_to_edge[host_ip] = (edge_switch_dpid, port_on_edge_switch)
        # Switch-to-host ports are discovered via PacketIn (ARP source learning).
        # Host IPs are known from the topo object and used to trigger route
        # installation as soon as all host ports have been learned.
        self.host_to_edge = {}

        # ip → mac, learned at runtime from ARP source fields
        self.arp_table = {}

        # Tracks whether inter-switch adjacency is ready (from get_link)
        self.topo_ready = False

        # Total expected switches for k=4: (k/2)^2 core + k*(k/2) agg + k*(k/2) edge
        self.total_switches = (self.k // 2) ** 2 + self.k * self.k

        # Full set of host IPs from the topo — used to detect when all hosts
        # have reported in so we can install the remaining pending routes.
        self.all_host_ips = set(s.ip for s in self.topo_net.servers)

    # -----------------------------------------------------------------------
    # TOPOLOGY DISCOVERY — Ryu EventSwitchEnter fires when each switch connects.
    # Once all switches are registered, call get_link() to read real port numbers.
    # -----------------------------------------------------------------------
    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        switch_list = get_switch(self, None)
        self.logger.info("Switch entered: %d / %d seen",
                         len(switch_list), self.total_switches)

        if len(switch_list) < self.total_switches:
            return  # wait until every switch has registered

        if self.topo_ready:
            return  # already built

        self.build_adjacency_from_ryu()

        # If all datapaths have also connected (OFPSwitchFeatures fired for all),
        # install routes immediately; otherwise the SwitchFeatures handler will
        # call install_all_routes() once the last datapath connects.
        if len(self.datapaths) == self.total_switches:
            self.install_all_routes()

    # -----------------------------------------------------------------------
    # BUILD ADJACENCY using Ryu get_link() — satisfies the lab requirement of
    # not assuming static switch-to-switch port mappings.
    # -----------------------------------------------------------------------
    def build_adjacency_from_ryu(self):
        link_list = get_link(self, None)
        self.adjacency = {}

        for link in link_list:
            src = link.src.dpid
            dst = link.dst.dpid
            port = link.src.port_no
            if src not in self.adjacency:
                self.adjacency[src] = {}
            self.adjacency[src][dst] = port

        self.topo_ready = True
        self.logger.info(
            "Adjacency built via get_link(): %d switches, %d directed links",
            len(self.adjacency),
            sum(len(v) for v in self.adjacency.values()),
        )

    # -----------------------------------------------------------------------
    # SWITCH FEATURES — fires when each switch's OpenFlow session is established.
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

        # If topology is already ready and this is the last datapath, install routes.
        if self.topo_ready and len(self.datapaths) == self.total_switches:
            self.install_all_routes()

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
    # Returns {dst_dpid: next_hop_dpid} from src_dpid.
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
    # INSTALL ROUTES FOR ALL KNOWN HOSTS
    # Called once when both adjacency (from get_link) AND all host attachment
    # ports (from ARP learning) are available.
    # -----------------------------------------------------------------------
    def install_all_routes(self):
        """
        Proactively install routes for every host whose edge-switch attachment
        port has already been learned via ARP.  Any host not yet seen will have
        its routes installed when it sends its first ARP (see handle_arp).
        """
        installed = 0
        for host_ip, (edge_dpid, host_port) in self.host_to_edge.items():
            self.install_host_routes(host_ip, edge_dpid, host_port)
            installed += 1
        self.logger.info("install_all_routes: pushed routes for %d hosts", installed)

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
                    self.logger.warning("dpid %d missing from adjacency", dpid)
                    continue
                next_hops = self.dijkstra(dpid)
                if edge_dpid not in next_hops:
                    self.logger.warning("No path: switch %d → %d", dpid, edge_dpid)
                    continue
                out_port = self.adjacency[dpid][next_hops[edge_dpid]]

            actions = [parser.OFPActionOutput(out_port)]

            match_ip  = parser.OFPMatch(eth_type=0x0800, ipv4_dst=host_ip)
            match_arp = parser.OFPMatch(eth_type=0x0806, arp_tpa=host_ip)
            self.add_flow(datapath, 1, match_ip,  actions)
            self.add_flow(datapath, 1, match_arp, actions)

        self.logger.info("Routes installed for host %s (edge sw %d port %d)",
                         host_ip, edge_dpid, host_port)

    # -----------------------------------------------------------------------
    # PACKET IN
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
        ip_pkt  = pkt.get_protocol(ipv4.ipv4)

        if arp_pkt:
            self.handle_arp(datapath, in_port, arp_pkt, msg)
        # IP packets hitting the controller means routes aren't installed yet —
        # drop silently to avoid loops.

    # -----------------------------------------------------------------------
    # ARP HANDLER
    # Two responsibilities:
    #   1. Learn host attachment point → install full fabric routes proactively.
    #   2. Answer ARP requests (unicast reply if MAC known, flood otherwise).
    # -----------------------------------------------------------------------
    def handle_arp(self, datapath, in_port, arp_pkt, msg):
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser

        src_ip  = arp_pkt.src_ip
        src_mac = arp_pkt.src_mac
        dst_ip  = arp_pkt.dst_ip

        # Learn MAC
        self.arp_table[src_ip] = src_mac

        # Learn host attachment and install routes (first time only)
        if src_ip not in self.host_to_edge:
            self.host_to_edge[src_ip] = (datapath.id, in_port)
            self.logger.info("Learned host %s → sw %d port %d",
                             src_ip, datapath.id, in_port)
            # Only install routes once inter-switch adjacency is ready
            if self.topo_ready:
                self.install_host_routes(src_ip, datapath.id, in_port)

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

        # Flood — ARP request with unknown target, or an ARP reply
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=[parser.OFPActionOutput(ofproto.OFPP_FLOOD)],
            data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        )
        datapath.send_msg(out)
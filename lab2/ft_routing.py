"""
 Copyright (c) 2025 Computer Networks Group @ UPB
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
import topo

class FTRouter(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(FTRouter, self).__init__(*args, **kwargs)

        # Initialize the topology
        self.k = 4
        self.topo_net = topo.Fattree(self.k)
        self.datapaths = {}

        self.adjacency = {}
        self.host_to_edge = {}
        self.node_to_dpid = {}
        self.topo_ready = False

    # ---- SWITCH CONNECTS ----
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.datapaths[datapath.id] = datapath

        # Default table-miss rule
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        # Build topology and routes once all switches connect
        total_switches = (self.k // 2)**2 + self.k * (self.k // 2) * 2
        if len(self.datapaths) == total_switches and not self.topo_ready:
            self.logger.info("All switches connected. Building Two-Level Routing Tables...")
            self.build_adjacency_from_topo()
            self.install_two_level_routes()

    # ---- ADD FLOW RULE ----
    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    # ---- BUILD ADJACENCY FROM TOPO ----
    def build_adjacency_from_topo(self):
        self.node_to_dpid = {id(sw): i + 1 for i, sw in enumerate(self.topo_net.switches)}
        num_sw = len(self.topo_net.switches)
        port_counter = {i + 1: 1 for i in range(num_sw)}

        self.adjacency = {i + 1: {} for i in range(num_sw)}
        self.host_to_edge = {}

        all_nodes = self.topo_net.switches + self.topo_net.servers
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

                l_port = None
                if l_is_sw:
                    l_dpid = self.node_to_dpid[id(lnode)]
                    l_port = port_counter[l_dpid]
                    port_counter[l_dpid] += 1

                r_port = None
                if r_is_sw:
                    r_dpid = self.node_to_dpid[id(rnode)]
                    r_port = port_counter[r_dpid]
                    port_counter[r_dpid] += 1

                if l_is_sw and r_is_sw:
                    self.adjacency[l_dpid][r_dpid] = l_port
                    self.adjacency[r_dpid][l_dpid] = r_port
                elif l_is_sw and not r_is_sw:
                    self.host_to_edge[rnode.ip] = (l_dpid, l_port)
                elif r_is_sw and not l_is_sw:
                    self.host_to_edge[lnode.ip] = (r_dpid, r_port)

        self.topo_ready = True

    # ---- AL-FARES TWO-LEVEL ROUTING ----
    def install_two_level_routes(self):
        """
        Installs Prefix (Intra-pod) and Suffix (Inter-pod) rules per Al-Fares Sec 3.5.
        """
        for node in self.topo_net.switches:
            dpid = self.node_to_dpid[id(node)]
            datapath = self.datapaths[dpid]
            parser = datapath.ofproto_parser

            # -------------------------------------
            # 1. CORE SWITCHES
            # -------------------------------------
            if node.type == 'core':
                # Route DOWN to pods based on /16 prefix
                for edge in node.edges:
                    nbr = edge.lnode if edge.rnode == node else edge.rnode
                    if nbr.type == 'agg':
                        pod = int(nbr.ip.split('.')[1])
                        out_port = self.adjacency[dpid][self.node_to_dpid[id(nbr)]]
                        
                        ip_prefix = f"10.{pod}.0.0"
                        mask = "255.255.0.0"

                        self._push_ip_and_arp(datapath, 1, ip_prefix, mask, out_port)

            # -------------------------------------
            # 2. AGGREGATION SWITCHES
            # -------------------------------------
            elif node.type == 'agg':
                pod = int(node.ip.split('.')[1])
                core_nbrs = []
                edge_nbrs = []
                
                for edge in node.edges:
                    nbr = edge.lnode if edge.rnode == node else edge.rnode
                    if nbr.type == 'core': core_nbrs.append(nbr)
                    if nbr.type == 'edge': edge_nbrs.append(nbr)

                core_nbrs = sorted(core_nbrs, key=lambda x: x.id)

                # Route DOWN to Edge Switches (Intra-pod Prefix, Priority 2)
                for nbr in edge_nbrs:
                    edge_idx = int(nbr.ip.split('.')[2])
                    out_port = self.adjacency[dpid][self.node_to_dpid[id(nbr)]]
                    ip_prefix = f"10.{pod}.{edge_idx}.0"
                    mask = "255.255.255.0"

                    self._push_ip_and_arp(datapath, 2, ip_prefix, mask, out_port)

                # Route UP to Core Switches (Inter-pod Suffix, Priority 1)
                for i, nbr in enumerate(core_nbrs):
                    host_id = i + 1
                    out_port = self.adjacency[dpid][self.node_to_dpid[id(nbr)]]
                    suffix = f"0.0.0.{host_id}"
                    mask = "0.0.0.255"

                    self._push_ip_and_arp(datapath, 1, suffix, mask, out_port)

            # -------------------------------------
            # 3. EDGE SWITCHES
            # -------------------------------------
            elif node.type == 'edge':
                agg_nbrs = []
                server_nbrs = []
                
                for edge in node.edges:
                    nbr = edge.lnode if edge.rnode == node else edge.rnode
                    if nbr.type == 'agg': agg_nbrs.append(nbr)
                    if nbr.type == 'server': server_nbrs.append(nbr)

                agg_nbrs = sorted(agg_nbrs, key=lambda x: x.id)

                # Route DOWN to Hosts (Exact Match, Priority 2)
                for nbr in server_nbrs:
                    host_ip = nbr.ip
                    out_port = self.host_to_edge[host_ip][1]

                    self._push_ip_and_arp(datapath, 2, host_ip, "255.255.255.255", out_port)

                # Route UP to Agg Switches (Inter-pod Suffix, Priority 1)
                for i, nbr in enumerate(agg_nbrs):
                    host_id = i + 1
                    out_port = self.adjacency[dpid][self.node_to_dpid[id(nbr)]]
                    suffix = f"0.0.0.{host_id}"
                    mask = "0.0.0.255"

                    self._push_ip_and_arp(datapath, 1, suffix, mask, out_port)

        self.logger.info("Two-Level Routing Tables successfully installed.")

    def _push_ip_and_arp(self, datapath, priority, ip_str, mask_str, out_port):
        """Helper to push identical rules for IP and ARP to ensure zero controller load."""
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(out_port)]

        if mask_str == "255.255.255.255":
            # Exact Match
            match_ip = parser.OFPMatch(eth_type=0x0800, ipv4_dst=ip_str)
            match_arp = parser.OFPMatch(eth_type=0x0806, arp_tpa=ip_str)
        else:
            # Masked Match (Prefix or Suffix)
            match_ip = parser.OFPMatch(eth_type=0x0800, ipv4_dst=(ip_str, mask_str))
            match_arp = parser.OFPMatch(eth_type=0x0806, arp_tpa=(ip_str, mask_str))

        self.add_flow(datapath, priority, match_ip, actions)
        self.add_flow(datapath, priority, match_arp, actions)

    # ---- PACKET IN HANDLER ----
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # Because we pushed hardware ARP routing alongside IP routing, 
        # the controller doesn't need to process ANY packets.
        pass
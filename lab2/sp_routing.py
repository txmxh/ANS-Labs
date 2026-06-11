#!/usr/bin/env python3

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, arp, ether_types
from ryu.topology import event
from ryu.topology.api import get_link

class SPRouter(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SPRouter, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.adjacency = {}       # dict of dicts: dpid_a -> {dpid_b: port_no}
        self.host_to_edge = {}    # ip -> (dpid, port_no)
        self.arp_table = {}       # ip -> mac

    # ---- SWITCH CONNECTS ----
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser

        self.datapaths[datapath.id] = datapath

        # Default table-miss rule: send unknown packets to controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    # ---- TOPOLOGY DISCOVERY (Dynamic) ----
    @set_ev_cls(event.EventSwitchEnter, MAIN_DISPATCHER)
    @set_ev_cls(event.EventLinkAdd, MAIN_DISPATCHER)
    def update_topology(self, ev):
        """
        Dynamically learn switch-to-switch links using Ryu APIs.
        No static mapping from topo.py allowed!
        """
        links = get_link(self, None)
        
        # Initialize adjacency for all known datapaths
        self.adjacency = {dp: {} for dp in self.datapaths}
        
        for link in links:
            src_dpid = link.src.dpid
            dst_dpid = link.dst.dpid
            self.adjacency.setdefault(src_dpid, {})[dst_dpid] = link.src.port_no
            self.adjacency.setdefault(dst_dpid, {})[src_dpid] = link.dst.port_no

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
        Calculates shortest path from src_dpid to all other switches.
        Returns a dict mapping {destination_dpid: next_hop_dpid}
        """
        dist = {dpid: float('inf') for dpid in self.datapaths}
        prev = {dpid: None for dpid in self.datapaths}
        dist[src_dpid] = 0
        unvisited = set(self.datapaths.keys())

        while unvisited:
            u = min(unvisited, key=lambda x: dist[x])
            if dist[u] == float('inf'):
                break   # Remaining nodes unreachable yet
            unvisited.remove(u)

            for neighbor, port in self.adjacency.get(u, {}).items():
                if neighbor in unvisited:
                    alt = dist[u] + 1
                    if alt < dist[neighbor]:
                        dist[neighbor] = alt
                        prev[neighbor] = u

        next_hop = {}
        for dst in self.datapaths:
            if dst == src_dpid: continue
            curr = dst
            while prev[curr] is not None and prev[curr] != src_dpid:
                curr = prev[curr]
            if prev[curr] == src_dpid:
                next_hop[dst] = curr

        return next_hop

    # ---- INSTALL IPv4 ROUTES ----
    def install_host_routes(self, host_ip, edge_dpid, host_port):
        """
        Pushes shortest-path IPv4 forwarding rules for a newly learned host
        to EVERY switch in the network.
        """
        for dpid, datapath in self.datapaths.items():
            parser = datapath.ofproto_parser

            if dpid == edge_dpid:
                out_port = host_port
            else:
                next_hops = self.dijkstra(dpid)
                if edge_dpid not in next_hops:
                    continue  # Topology might still be converging
                next_dpid = next_hops[edge_dpid]
                out_port  = self.adjacency[dpid][next_dpid]

            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=host_ip)
            actions = [parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, 10, match, actions)

    # ---- CONTROLLER PACKET ROUTING ----
    def forward_to_host(self, msg, host_ip):
        """Forwards an encapsulated packet directly to a known host."""
        target_dpid, target_port = self.host_to_edge[host_ip]
        datapath = self.datapaths[target_dpid]
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        
        actions = [parser.OFPActionOutput(target_port)]
        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=msg.data)
        datapath.send_msg(out)

    def flood_to_edges(self, msg):
        """
        Safe flood: Sends the packet ONLY out of edge ports (ports not connected 
        to other switches). This prevents broadcast storms in the fat-tree.
        """
        in_dpid = msg.datapath.id
        in_port = msg.match['in_port']
        
        for dpid, datapath in self.datapaths.items():
            parser = datapath.ofproto_parser
            ofproto = datapath.ofproto
            
            # Identify ports connected to other switches
            inter_sw_ports = set(self.adjacency.get(dpid, {}).values())
            out_ports = []
            
            for port in datapath.ports.values():
                port_no = port.port_no
                if port_no > ofproto.OFPP_MAX:
                    continue
                # If port is NOT a switch-to-switch link, it's an edge (host) port
                if port_no not in inter_sw_ports:
                    # Don't bounce it back down the exact port it just came from
                    if dpid == in_dpid and port_no == in_port:
                        continue
                    out_ports.append(port_no)
                    
            if out_ports:
                actions = [parser.OFPActionOutput(p) for p in out_ports]
                out = parser.OFPPacketOut(
                    datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                    in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=msg.data)
                datapath.send_msg(out)

    # ---- PACKET IN HANDLER ----
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        # Ignore Link Layer Discovery Protocol (Ryu uses this to map topology)
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        src_ip = None
        dst_ip = None

        if arp_pkt:
            src_ip = arp_pkt.src_ip
            dst_ip = arp_pkt.dst_ip
            self.arp_table[src_ip] = arp_pkt.src_mac
        elif ip_pkt:
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst

        # 1. DYNAMIC LEARNING: First time a host speaks, learn its location and push routes
        if src_ip and src_ip not in self.host_to_edge:
            self.logger.info("Learned Host %s at Switch %d, Port %d", src_ip, dpid, in_port)
            self.host_to_edge[src_ip] = (dpid, in_port)
            self.install_host_routes(src_ip, dpid, in_port)

        # 2. PACKET HANDLING
        if arp_pkt:
            if arp_pkt.opcode == arp.ARP_REQUEST:
                if dst_ip in self.host_to_edge:
                    self.forward_to_host(msg, dst_ip)
                else:
                    self.flood_to_edges(msg)
            elif arp_pkt.opcode == arp.ARP_REPLY:
                if dst_ip in self.host_to_edge:
                    self.forward_to_host(msg, dst_ip)

        elif ip_pkt:
            # If an IP packet reaches the controller, it usually means the 
            # route was literally just installed and this packet was caught in flight.
            if dst_ip in self.host_to_edge:
                self.forward_to_host(msg, dst_ip)
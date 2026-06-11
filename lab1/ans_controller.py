"""
 Copyright (c) 2026 Computer Networks Group @ UPB

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

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4, icmp, tcp, udp, ether_types

class LearningSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LearningSwitch, self).__init__(*args, **kwargs)

        # Here you can initialize the data structures you want to keep at the controller

        self.mac_table = {}
        self.arp_table = {}
        self.router_dpid = 3

        # Packets waiting for ARP reply: {dst_ip: [(datapath, raw_data), ...]}
        self.pending_packets = {}

        self.router_port_to_mac = {
            1: "00:00:00:00:01:03",  # ext host
            2: "00:00:00:00:01:01",  # s1 switch (h1, h2)
            3: "00:00:00:00:01:02",  # s2 switch (ser)
        }
        self.router_port_to_ip = {
            1: "192.168.1.1",
            2: "10.0.1.1",
            3: "10.0.2.1",
        }
        self.router_ip_to_port = {p: i for i, p in self.router_port_to_ip.items()}
        self.subnet_to_port = {
            "192.168.1": 1,
            "10.0.1": 2,
            "10.0.2": 3,
        }

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Initial flow entry for matching misses
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info("Switch connected with dpid: %s", datapath.id)

        # Pre-install blocking rule on router as soon as it connects
        if datapath.id == self.router_dpid:
            block_match = parser.OFPMatch(
                in_port=1,
                eth_type=ether_types.ETH_TYPE_IP
            )
            self.add_drop_flow(datapath, 10, block_match)
            self.logger.info("Blocking rule installed on router")

    # Add a flow entry to the flow-table   
    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Construct flow_mod message and send it
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    def add_drop_flow(self, datapath, priority, match):
        parser = datapath.ofproto_parser
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=[]  # no instructions = drop
        )
        datapath.send_msg(mod)

    def send_packet(self, datapath, port, data):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(port)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=data
        )
        datapath.send_msg(out)

    # Handle the packet_in event
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        
        msg = ev.msg
        datapath = msg.datapath

        # Your controller implementation should start here
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return

        if self.router_dpid is not None and dpid == self.router_dpid:
            self.handle_router(datapath, in_port, pkt, eth, msg.data)
            return

        # ======== SWITCH LOGIC ========
        dst_mac = eth.dst
        src_mac = eth.src

        if dpid not in self.mac_table:
            self.mac_table[dpid] = {}

        self.mac_table[dpid][src_mac] = in_port

        if dst_mac in self.mac_table[dpid]:
            out_port = self.mac_table[dpid][dst_mac]
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac)
            actions = [parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, 1, match, actions)
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        )
        datapath.send_msg(out)

    # ======== ROUTER LOGIC ========
    def handle_router(self, datapath, in_port, pkt, eth, raw_data):
        arp_pkt  = pkt.get_protocol(arp.arp)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)

        if arp_pkt:
            self.handle_router_arp(datapath, in_port, eth, arp_pkt)
        elif ipv4_pkt:
            self.handle_router_ip(datapath, in_port, eth, ipv4_pkt, pkt, raw_data)

    def handle_router_arp(self, datapath, in_port, eth, arp_pkt):
        # Learn sender's IP → MAC
        self.arp_table[arp_pkt.src_ip] = arp_pkt.src_mac

        # If any packets were waiting for this IP, send them now
        learned_ip = arp_pkt.src_ip
        if learned_ip in self.pending_packets:
            for (dp, rd) in self.pending_packets[learned_ip]:
                self.forward_buffered_packet(dp, rd, learned_ip)
            del self.pending_packets[learned_ip]

        target_ip = arp_pkt.dst_ip

        # Reply if someone is asking for one of the router's IPs
        if target_ip in self.router_ip_to_port:
            router_port = self.router_ip_to_port[target_ip]
            router_mac  = self.router_port_to_mac[router_port]

            arp_reply = packet.Packet()
            arp_reply.add_protocol(ethernet.ethernet(
                dst=eth.src,
                src=router_mac,
                ethertype=ether_types.ETH_TYPE_ARP
            ))
            arp_reply.add_protocol(arp.arp(
                opcode=arp.ARP_REPLY,
                src_mac=router_mac,
                src_ip=target_ip,
                dst_mac=arp_pkt.src_mac,
                dst_ip=arp_pkt.src_ip
            ))
            arp_reply.serialize()
            self.send_packet(datapath, in_port, arp_reply.data)

    def handle_router_ip(self, datapath, in_port, eth, ipv4_pkt, pkt, raw_data):
        parser = datapath.ofproto_parser
        src_ip = ipv4_pkt.src
        dst_ip = ipv4_pkt.dst

        # ---- HANDLE ICMP TO ROUTER'S OWN IPs ----
        # e.g. h1 pinging its own gateway 10.0.1.1
        if dst_ip in self.router_ip_to_port:
            expected_port = self.router_ip_to_port[dst_ip]
            if in_port == expected_port:
                # Host is pinging its own gateway - reply
                icmp_pkt = pkt.get_protocol(icmp.icmp)
                if icmp_pkt and icmp_pkt.type == icmp.ICMP_ECHO_REQUEST:
                    self.send_icmp_reply(datapath, in_port, eth, ipv4_pkt, icmp_pkt)
            return

        # ---- BLOCKING RULES ----
        if in_port == 1:
            self.add_drop_flow(datapath, 10,
                parser.OFPMatch(in_port=1, eth_type=ether_types.ETH_TYPE_IP))
            return

        # Block TCP/UDP going to ext
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)
        if tcp_pkt or udp_pkt:
            dst_prefix = ".".join(dst_ip.split(".")[:3])
            if dst_prefix == "192.168.1":
                self.add_drop_flow(datapath, 10,
                    parser.OFPMatch(
                        in_port=in_port,
                        eth_type=ether_types.ETH_TYPE_IP,
                        ip_proto=6 if tcp_pkt else 17
                    ))
                return

        # ---- FIND OUTPUT PORT ----
        dst_prefix = ".".join(dst_ip.split(".")[:3])
        if dst_prefix not in self.subnet_to_port:
            return

        out_port = self.subnet_to_port[dst_prefix]

        # Don't know dst MAC yet — buffer packet and send ARP
        if dst_ip not in self.arp_table:
            if dst_ip not in self.pending_packets:
                self.pending_packets[dst_ip] = []
            self.pending_packets[dst_ip].append((datapath, raw_data))
            self.send_arp_request(datapath, out_port, dst_ip)
            return

        # We know the MAC — forward it
        self.forward_packet(datapath, raw_data, dst_ip)

    def forward_packet(self, datapath, raw_data, dst_ip):
        # Forward a packet to dst_ip, rewriting MACs
        parser = datapath.ofproto_parser
        dst_prefix = ".".join(dst_ip.split(".")[:3])
        out_port = self.subnet_to_port[dst_prefix]
        dst_mac  = self.arp_table[dst_ip]
        src_mac  = self.router_port_to_mac[out_port]

        # Install flow rule for future packets to same IP
        actions = [
            parser.OFPActionSetField(eth_src=src_mac),
            parser.OFPActionSetField(eth_dst=dst_mac),
            parser.OFPActionOutput(out_port)
        ]
        match = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_dst=dst_ip
        )
        self.add_flow(datapath, 5, match, actions)

        # Send the packet now
        pkt_in = packet.Packet(raw_data)
        new_pkt = packet.Packet()
        new_pkt.add_protocol(ethernet.ethernet(
            dst=dst_mac,
            src=src_mac,
            ethertype=ether_types.ETH_TYPE_IP
        ))
        for proto in pkt_in.protocols[1:]:
            new_pkt.add_protocol(proto)
        new_pkt.serialize()
        self.send_packet(datapath, out_port, new_pkt.data)

    def forward_buffered_packet(self, datapath, raw_data, dst_ip):
        # Same as forward_packet — used when ARP reply arrives
        self.forward_packet(datapath, raw_data, dst_ip)

    def send_icmp_reply(self, datapath, in_port, eth, ipv4_pkt, icmp_pkt):
        # Router replies to ping directed at its own IP
        router_mac = self.router_port_to_mac[in_port]
        router_ip  = self.router_port_to_ip[in_port]

        reply = packet.Packet()
        reply.add_protocol(ethernet.ethernet(
            dst=eth.src,
            src=router_mac,
            ethertype=ether_types.ETH_TYPE_IP
        ))
        reply.add_protocol(ipv4.ipv4(
            dst=ipv4_pkt.src,
            src=router_ip,
            proto=1  # ICMP protocol number
        ))
        reply.add_protocol(icmp.icmp(
            type_=icmp.ICMP_ECHO_REPLY,
            code=0,
            csum=0,
            data=icmp_pkt.data  # echo back same data
        ))
        reply.serialize()
        self.send_packet(datapath, in_port, reply.data)

    def send_arp_request(self, datapath, out_port, target_ip):
        src_mac = self.router_port_to_mac[out_port]
        src_ip  = self.router_port_to_ip[out_port]

        arp_req = packet.Packet()
        arp_req.add_protocol(ethernet.ethernet(
            dst="ff:ff:ff:ff:ff:ff",
            src=src_mac,
            ethertype=ether_types.ETH_TYPE_ARP
        ))
        arp_req.add_protocol(arp.arp(
            opcode=arp.ARP_REQUEST,
            src_mac=src_mac,
            src_ip=src_ip,
            dst_mac="00:00:00:00:00:00",
            dst_ip=target_ip
        ))
        arp_req.serialize()
        self.send_packet(datapath, out_port, arp_req.data)
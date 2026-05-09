from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4, icmp


class LearningSwitch(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):

        super(LearningSwitch, self).__init__(*args, **kwargs)

        ############################################################
        # Router interface MAC addresses
        ############################################################

        self.port_to_own_mac = {
            1: "00:00:00:00:01:01",
            2: "00:00:00:00:01:02",
            3: "00:00:00:00:01:03"
        }

        ############################################################
        # Router interface IP addresses
        ############################################################

        self.port_to_own_ip = {
            1: "10.0.1.1",
            2: "10.0.2.1",
            3: "192.168.1.1"
        }

        ############################################################
        # Switch MAC learning tables
        ############################################################

        self.mac_to_port = {}

        ############################################################
        # Static ARP table
        ############################################################

        self.arp_table = {
            "10.0.1.2": "00:00:00:00:00:01",
            "10.0.1.3": "00:00:00:00:00:02",
            "10.0.2.2": "00:00:00:00:00:03",
            "192.168.1.123": "00:00:00:00:00:04"
        }

    ################################################################
    # Add forwarding flow
    ################################################################

    def add_flow(self, datapath, priority, match, actions):

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [
            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                actions
            )
        ]

        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst
        )

        datapath.send_msg(mod)

    ################################################################
    # Add DROP flow
    ################################################################

    def add_drop_flow(self, datapath, priority, match):

        parser = datapath.ofproto_parser

        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=[]
        )

        datapath.send_msg(mod)

    ################################################################
    # Switch features
    ################################################################

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):

        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.logger.info("Connected switch DPID = %s", datapath.id)

        ############################################################
        # Table miss flow
        ############################################################

        match = parser.OFPMatch()

        actions = [
            parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER
            )
        ]

        self.add_flow(datapath, 0, match, actions)

    ################################################################
    # Main packet handler
    ################################################################

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):

        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        dpid = datapath.id
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)

        eth = pkt.get_protocol(ethernet.ethernet)

        if eth is None:
            return

        ############################################################
        # Ignore LLDP
        ############################################################

        if eth.ethertype == 0x88cc:
            return

        src = eth.src
        dst = eth.dst

        arp_pkt = pkt.get_protocol(arp.arp)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        icmp_pkt = pkt.get_protocol(icmp.icmp)

        ################################################################
        # ROUTER LOGIC (s3)
        ################################################################

        if dpid == 3:

            ############################################################
            # Learn ARP dynamically
            ############################################################

            if arp_pkt:
                self.arp_table[arp_pkt.src_ip] = arp_pkt.src_mac

            ############################################################
            # Handle ARP requests
            ############################################################

            if arp_pkt and arp_pkt.opcode == arp.ARP_REQUEST:

                target_ip = arp_pkt.dst_ip

                if target_ip in self.port_to_own_ip.values():

                    ####################################################
                    # Only allow access to own gateway
                    ####################################################

                    if target_ip != self.port_to_own_ip[in_port]:
                        return

                    router_mac = self.port_to_own_mac[in_port]

                    arp_reply = packet.Packet()

                    arp_reply.add_protocol(
                        ethernet.ethernet(
                            ethertype=0x0806,
                            src=router_mac,
                            dst=src
                        )
                    )

                    arp_reply.add_protocol(
                        arp.arp(
                            opcode=arp.ARP_REPLY,
                            src_mac=router_mac,
                            src_ip=target_ip,
                            dst_mac=arp_pkt.src_mac,
                            dst_ip=arp_pkt.src_ip
                        )
                    )

                    arp_reply.serialize()

                    actions = [
                        parser.OFPActionOutput(in_port)
                    ]

                    out = parser.OFPPacketOut(
                        datapath=datapath,
                        buffer_id=ofproto.OFP_NO_BUFFER,
                        in_port=ofproto.OFPP_CONTROLLER,
                        actions=actions,
                        data=arp_reply.data
                    )

                    datapath.send_msg(out)

                return

            ############################################################
            # IPv4 routing
            ############################################################

            if ipv4_pkt:

                src_ip = ipv4_pkt.src
                dst_ip = ipv4_pkt.dst

                ########################################################
                # BLOCK: ext -> internal ICMP
                ########################################################

                if (
                    src_ip.startswith("192.168.1.")
                    and
                    (
                        dst_ip.startswith("10.0.1.")
                        or
                        dst_ip.startswith("10.0.2.")
                    )
                    and icmp_pkt
                ):

                    match = parser.OFPMatch(
                        eth_type=0x0800,
                        ipv4_src=src_ip,
                        ipv4_dst=dst_ip,
                        ip_proto=1
                    )

                    self.add_drop_flow(datapath, 100, match)

                    return

                ########################################################
                # BLOCK: ext <-> ser
                ########################################################

                if (
                    (
                        src_ip.startswith("192.168.1.")
                        and dst_ip == "10.0.2.2"
                    )
                    or
                    (
                        src_ip == "10.0.2.2"
                        and dst_ip.startswith("192.168.1.")
                    )
                ):

                    match = parser.OFPMatch(
                        eth_type=0x0800,
                        ipv4_src=src_ip,
                        ipv4_dst=dst_ip
                    )

                    self.add_drop_flow(datapath, 100, match)

                    return

                ########################################################
                # Determine output port
                ########################################################

                out_port = None

                if dst_ip.startswith("10.0.1."):
                    out_port = 1

                elif dst_ip.startswith("10.0.2."):
                    out_port = 2

                elif dst_ip.startswith("192.168.1."):
                    out_port = 3

                if out_port is None:
                    return

                ########################################################
                # Resolve destination MAC
                ########################################################

                if dst_ip not in self.arp_table:
                    return

                dst_mac = self.arp_table[dst_ip]
                src_mac = self.port_to_own_mac[out_port]

                ########################################################
                # Router forwarding actions
                ########################################################

                actions = [
                    parser.OFPActionSetField(eth_src=src_mac),
                    parser.OFPActionSetField(eth_dst=dst_mac),
                    parser.OFPActionDecNwTtl(),
                    parser.OFPActionOutput(out_port)
                ]

                ########################################################
                # Install routing flow
                ########################################################

                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_type=0x0800,
                    ipv4_src=src_ip,
                    ipv4_dst=dst_ip
                )

                self.add_flow(datapath, 10, match, actions)

                ########################################################
                # Forward packet
                ########################################################

                out = parser.OFPPacketOut(
                    datapath=datapath,
                    buffer_id=msg.buffer_id,
                    in_port=in_port,
                    actions=actions,
                    data=(
                        msg.data
                        if msg.buffer_id == ofproto.OFP_NO_BUFFER
                        else None
                    )
                )

                datapath.send_msg(out)

        ################################################################
        # SWITCH LOGIC (s1 and s2)
        ################################################################

        else:

            self.mac_to_port.setdefault(dpid, {})

            ############################################################
            # Learn MAC
            ############################################################

            self.mac_to_port[dpid][src] = in_port

            ############################################################
            # Lookup destination
            ############################################################

            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
            else:
                out_port = ofproto.OFPP_FLOOD

            actions = [
                parser.OFPActionOutput(out_port)
            ]

            ############################################################
            # Install switch flow
            ############################################################

            if out_port != ofproto.OFPP_FLOOD:

                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_src=src,
                    eth_dst=dst
                )

                self.add_flow(datapath, 1, match, actions)

            ############################################################
            # Send packet
            ############################################################

            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=msg.buffer_id,
                in_port=in_port,
                actions=actions,
                data=(
                    msg.data
                    if msg.buffer_id == ofproto.OFP_NO_BUFFER
                    else None
                )
            )

            datapath.send_msg(out)
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4


class LearningSwitch(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LearningSwitch, self).__init__(*args, **kwargs)

        # Router interfaces
        self.port_to_own_mac = {
            1: "00:00:00:00:01:01",
            2: "00:00:00:00:01:02",
            3: "00:00:00:00:01:03"
        }

        self.port_to_own_ip = {
            1: "10.0.1.1",
            2: "10.0.2.1",
            3: "192.168.1.1"
        }

        # Learning switch tables
        self.mac_to_port = {}

        # ARP table (static for assignment)
        self.arp_table = {
            "10.0.1.2": "00:00:00:00:00:01",
            "10.0.1.3": "00:00:00:00:00:02",
            "10.0.2.2": "00:00:00:00:00:03",
            "192.168.1.123": "00:00:00:00:00:04"
        }

    # --------------------------------------------------
    # FLOW INSTALL
    # --------------------------------------------------
    def add_flow(self, datapath, priority, match, actions):

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [
            parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)
        ]

        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst
        )

        datapath.send_msg(mod)

    # --------------------------------------------------
    # TABLE MISS
    # --------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):

        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        match = parser.OFPMatch()

        actions = [
            parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)
        ]

        self.add_flow(datapath, 0, match, actions)

    # --------------------------------------------------
    # MAIN HANDLER
    # --------------------------------------------------
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

        if eth.ethertype == 0x88cc:
            return

        src = eth.src
        dst = eth.dst

        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)

        # ==========================================================
        # SWITCH LOGIC (s1, s2)
        # ==========================================================
        if dpid != 3:

            self.mac_to_port.setdefault(dpid, {})
            self.mac_to_port[dpid][src] = in_port

            out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)

            actions = [parser.OFPActionOutput(out_port)]

            if out_port != ofproto.OFPP_FLOOD:
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
                self.add_flow(datapath, 1, match, actions)

            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=msg.buffer_id,
                in_port=in_port,
                actions=actions,
                data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
            )

            datapath.send_msg(out)
            return

        # ==========================================================
        # ROUTER LOGIC (s3)
        # ==========================================================
        if not ipv4_pkt:
            return

        src_ip = ipv4_pkt.src
        dst_ip = ipv4_pkt.dst

        # ---------------- FIREWALL RULES ----------------

        # Block external -> internal
        if src_ip == "192.168.1.123" and dst_ip.startswith(("10.0.1.", "10.0.2.")):
            return

        # Block server <-> external
        if (src_ip == "192.168.1.123" and dst_ip == "10.0.2.2") or \
           (src_ip == "10.0.2.2" and dst_ip == "192.168.1.123"):
            return

        # ---------------- ROUTING ----------------

        if dst_ip.startswith("10.0.1."):
            out_port = 1
        elif dst_ip.startswith("10.0.2."):
            out_port = 2
        elif dst_ip.startswith("192.168.1."):
            out_port = 3
        else:
            return

        if dst_ip not in self.arp_table:
            return

        dst_mac = self.arp_table[dst_ip]
        src_mac = self.port_to_own_mac[out_port]

        actions = [
            parser.OFPActionSetField(eth_src=src_mac),
            parser.OFPActionSetField(eth_dst=dst_mac),
            parser.OFPActionOutput(out_port)
        ]

        match = parser.OFPMatch(eth_type=0x0800, ipv4_dst=dst_ip)

        self.add_flow(datapath, 10, match, actions)

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        )

        datapath.send_msg(out)
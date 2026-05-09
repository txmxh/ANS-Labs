from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4, icmp

class LearningSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LearningSwitch, self).__init__(*args, **kwargs)
        # Router configurations from manual
        self.port_to_own_mac = {1: "00:00:00:00:01:01", 2: "00:00:00:00:01:02", 3: "00:00:00:00:01:03"}
        self.port_to_own_ip = {1: "10.0.1.1", 2: "10.0.2.1", 3: "192.168.1.1"}
        # Per-switch MAC table
        self.mac_to_port = {}
        # Router's ARP cache to remember host MACs
        self.arp_table = {"10.0.1.2": "00:00:00:00:00:01", "10.0.1.3": "00:00:00:00:00:02", 
                          "10.0.2.2": "00:00:00:00:00:03", "192.168.1.123": "00:00:00:00:00:04"}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        dpid = datapath.id

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if not eth: return
        
        dst_mac, src_mac = eth.dst, eth.src
        arp_pkt = pkt.get_protocol(arp.arp)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)

        if dpid == 3:  # Router Logic (s3)
            if arp_pkt and arp_pkt.opcode == arp.ARP_REQUEST:
                target_ip = arp_pkt.dst_ip
                if target_ip == self.port_to_own_ip.get(in_port):
                    router_mac = self.port_to_own_mac[in_port]
                    reply = packet.Packet()
                    reply.add_protocol(ethernet.ethernet(dst=src_mac, src=router_mac, ethertype=eth.ethertype))
                    reply.add_protocol(arp.arp(opcode=arp.ARP_REPLY, src_mac=router_mac, src_ip=target_ip, 
                                               dst_mac=src_mac, dst_ip=arp_pkt.src_ip))
                    reply.serialize()
                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, 
                                              in_port=ofproto.OFPP_CONTROLLER, actions=[parser.OFPActionOutput(in_port)], data=reply.data)
                    datapath.send_msg(out)

            elif ipv4_pkt:
                # Security: Block external discovery pings
                if ipv4_pkt.src.startswith('192.168.1') and pkt.get_protocol(icmp.icmp): return
                # Security: Block ext <-> ser connections
                if (ipv4_pkt.src == '192.168.1.123' and ipv4_pkt.dst == '10.0.2.2') or \
                   (ipv4_pkt.src == '10.0.2.2' and ipv4_pkt.dst == '192.168.1.123'): return
                # Security: Only allow pinging own gateway
                if ipv4_pkt.dst in self.port_to_own_ip.values() and ipv4_pkt.dst != self.port_to_own_ip.get(in_port): return

                # Routing Logic
                out_port = None
                if ipv4_pkt.dst.startswith('10.0.1'): out_port = 1
                elif ipv4_pkt.dst.startswith('10.0.2'): out_port = 2
                elif ipv4_pkt.dst.startswith('192.168.1'): out_port = 3

                if out_port:
                    host_mac = self.arp_table.get(ipv4_pkt.dst)
                    if host_mac:
                        actions = [parser.OFPActionDecNwTtl(), 
                                   parser.OFPActionSetField(eth_src=self.port_to_own_mac[out_port]), 
                                   parser.OFPActionSetField(eth_dst=host_mac),
                                   parser.OFPActionOutput(out_port)]
                        match = parser.OFPMatch(eth_type=0x0800, ipv4_dst=ipv4_pkt.dst)
                        self.add_flow(datapath, 1, match, actions)
                        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, 
                                                  actions=actions, data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None)
                        datapath.send_msg(out)

        else:  # Learning Switch Logic (s1/s2)
            self.mac_to_port.setdefault(dpid, {})
            self.mac_to_port[dpid][src_mac] = in_port
            out_port = self.mac_to_port[dpid].get(dst_mac, ofproto.OFPP_FLOOD)
            actions = [parser.OFPActionOutput(out_port)]
            if out_port != ofproto.OFPP_FLOOD:
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac)
                self.add_flow(datapath, 1, match, actions)
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, 
                                      data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None)
            datapath.send_msg(out)
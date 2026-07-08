#include <core.p4>
#include <v1model.p4>

// L2 switch extended with an in-network ARP proxy:
// ARP requests for known hosts are answered by the switch itself
// (the request is rewritten into a reply and bounced out the ingress port).
// Everything else is forwarded like the reference l2/switch.p4.

const bit<16> ETH_TYPE_ARP = 0x0806;
const bit<16> ARP_REQUEST = 1;
const bit<16> ARP_REPLY   = 2;
const bit<32> PKT_INSTANCE_TYPE_REPLICATION = 5;

header ethernet_t {
  bit<48> dstAddr;
  bit<48> srcAddr;
  bit<16> etherType;
}

// ARP over Ethernet/IPv4 (htype=1, ptype=0x0800, hlen=6, plen=4)
header arp_t {
  bit<16> htype;
  bit<16> ptype;
  bit<8>  hlen;
  bit<8>  plen;
  bit<16> oper;
  bit<48> sha;   // sender hardware address
  bit<32> spa;   // sender protocol address
  bit<48> tha;   // target hardware address
  bit<32> tpa;   // target protocol address
}

struct headers_t {
  ethernet_t ethernet;
  arp_t      arp;
}

struct metadata_t { }

parser parse(packet_in pkt, out headers_t hdr,
             inout metadata_t meta, inout standard_metadata_t std) {
  state start {
    pkt.extract(hdr.ethernet);
    transition select(hdr.ethernet.etherType) {
      ETH_TYPE_ARP : parse_arp;   // this is how we tell ARP from non-ARP traffic
      default      : accept;
    }
  }
  state parse_arp {
    pkt.extract(hdr.arp);
    transition accept;
  }
}

control ingress(inout headers_t hdr,
                inout metadata_t meta, inout standard_metadata_t std) {

  // ---------------- standard L2 forwarding (as in l2/switch.p4) ------------
  register<bit<16>>(1) flood_mgid;

  action flood() { flood_mgid.read(std.mcast_grp, 0); }
  action forward(bit<9> port) { std.egress_spec = port; }

  table dmac {
    key            = { hdr.ethernet.dstAddr : exact; }
    actions        = { forward; flood; }
    size           = 4096;
    default_action = flood();
  }

  // ---------------- ARP proxy ----------------------------------------------
  bit<32> req_tpa;

  // Rewrite the ARP request in place into an ARP reply and send it
  // back out the port it came in from. `mac` is the MAC that owns
  // the requested IP (installed by the controller).
  action arp_reply(bit<48> mac) {
    hdr.arp.oper = ARP_REPLY;
    req_tpa      = hdr.arp.tpa;
    hdr.arp.tha  = hdr.arp.sha;   // target <- requester
    hdr.arp.tpa  = hdr.arp.spa;
    hdr.arp.sha  = mac;           // sender <- owner of the requested IP
    hdr.arp.spa  = req_tpa;

    hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
    hdr.ethernet.srcAddr = mac;

    std.egress_spec = std.ingress_port;
  }

  table arp_tbl {
    key            = { hdr.arp.tpa : exact; }   // who is being asked for?
    actions        = { arp_reply; NoAction; }
    size           = 4096;
    default_action = NoAction();
  }

  apply {
    bool answered = false;
    if (hdr.arp.isValid() && hdr.arp.oper == ARP_REQUEST) {
      answered = arp_tbl.apply().hit;
    }
    if (!answered) {
      // Non-ARP traffic, ARP replies, and requests for unknown IPs
      // are forwarded/flooded like a normal L2 switch.
      dmac.apply();
    }
  }
}

control egress(inout headers_t hdr,
               inout metadata_t meta, inout standard_metadata_t std) {
  apply {
    // Filter out the flooded copy that would loop back out the ingress port
    if (std.instance_type == PKT_INSTANCE_TYPE_REPLICATION &&
        std.egress_port == std.ingress_port) {
      mark_to_drop(std);
    }
  }
}

control deparse(packet_out pkt, in headers_t hdr) {
  apply {
    pkt.emit(hdr.ethernet);
    pkt.emit(hdr.arp);   // only emitted when valid
  }
}

control no_checksum(inout headers_t hdr, inout metadata_t meta) { apply {  } }

V1Switch(parse(),no_checksum(),ingress(),egress(),no_checksum(),deparse()) main;

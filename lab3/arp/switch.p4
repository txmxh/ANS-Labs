#include <core.p4>
#include <v1model.p4>

// TODO: Extend and L2 switch with ARP resolution support

const bit<16> ETH_TYPE_ARP = 0x0806;
const bit<16> ARP_REQUEST = 1;
const bit<16> ARP_REPLY   = 2;
const bit<32> PKT_INSTANCE_TYPE_REPLICATION = 5;

header ethernet_t {
  bit<48> dstAddr;
  bit<48> srcAddr;
  bit<16> etherType;
}

struct headers_t {
  // TODO: Implement me
}

struct metadata_t { }

parser parse(packet_in pkt, out headers_t hdr,
             inout metadata_t meta, inout standard_metadata_t std) {
  // TODO: Implement me
}

control ingress(inout headers_t hdr,
                inout metadata_t meta, inout standard_metadata_t std) {
  // TODO: Implement me
}

control egress(inout headers_t hdr,
               inout metadata_t meta, inout standard_metadata_t std) {
  // TODO: Implement me
}

control deparse(packet_out pkt, in headers_t hdr) {
  // TODO: Implement me
}

control no_checksum(inout headers_t hdr, inout metadata_t meta) { apply {  } }

V1Switch(parse(),no_checksum(),ingress(),egress(),no_checksum(),deparse()) main;

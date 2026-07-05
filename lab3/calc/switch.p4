#include <core.p4>
#include <v1model.p4>

header ethernet_t {
  bit<48> dstAddr;
  bit<48> srcAddr;
  bit<16> etherType;
}

header calc_t {
  bit<8> op;
  int<32> a;
  int<32> b;
}

struct headers_t {
  ethernet_t eth;
  calc_t calc;
}

struct metadata_t { }

parser parse(packet_in pkt, out headers_t hdr,
             inout metadata_t meta, inout standard_metadata_t std) {
  // TODO: Implement me
}

// === IMPORTANT NOTE ===
//
// There is currently a bug with the BMv2 switch P4 compiler
// When reading a signed register, and then using the result for a signed operation,
// the switch actually performs that operation as unsigned instead. This is usually
// fine (e.g. add/sub works fine), but comparissons can fail. This can cause your
// your min/max/shl/shr operations to fail. To avoid it please use the SIGNED macro
// For example:
//
//      int<32> val = -42;
//      signed_register.read(val, 0)
//      if (val < 42) ...         // This will return false
//      if (SIGNED(32,val) < 42) ... // This will return true
//
#define SIGNED(bits,var) ((int<bits>)(bit<bits>)var)

control calculator(inout headers_t hdr, inout metadata_t meta,
                   inout standard_metadata_t std) {

  action add() { hdr.calc.a = hdr.calc.a + hdr.calc.b; }

  // TODO: Implement the remaining calculator block
  //
  // - Implement the operations according to their specification
  // - Apply the one requested in the calc header (use a table)
  // - Decide how to handle sending the result back. Should that
  //   be handled here, or fall through to standard forwarding?

  apply() { }
}

control ingress(inout headers_t hdr, inout metadata_t meta,
                inout standard_metadata_t std) {
  calculator() calc;

  // TODO: Implement the remaining ingress block
  //
  // - The calculator logic should only run on calc packets.
  //   Other packets should be forwarded normally
  // - For calculator packets think how to send a result back

  apply { }
}

control egress(inout headers_t hdr, inout metadata_t meta,
               inout standard_metadata_t std) {
  // TODO: Implement me
  apply { }
}

control deparse(packet_out pkt, in headers_t hdr) {
  // TODO: Implement me
  apply { }
}

control no_checksum(inout headers_t hdr, inout metadata_t meta) { apply {  } }

V1Switch(parse(),no_checksum(),ingress(),egress(),no_checksum(),deparse()) main;

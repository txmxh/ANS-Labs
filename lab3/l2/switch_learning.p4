#include <core.p4>
#include <v1model.p4>

header ethernet_t {
  bit<48> dstAddr;
  bit<48> srcAddr;
  bit<16> etherType;
}

struct headers_t {
  // Here you declare all possible headers your switch may process
  // The parser populates the struct accordingly
  ethernet_t ethernet;
}

struct metadata_t {
  // Here you can declare variables that you want to pass
  // between the top-level controls, e.g. ingress -> egress
}

// This struct is sent to the controller as a digest
struct learn_t { bit<48> mac; bit<9>  ingress_port; }

parser parse(packet_in pkt, out headers_t hdr,
             inout metadata_t meta, inout standard_metadata_t std) {
  state start {
    // Extracting a header makes it "valid" automatically,
    // After the next line hdr.ethernet.isValid() returns
    // true, unless you explicitly invalidate it
    pkt.extract(hdr.ethernet);
    transition accept;
  }
}

control ingress(inout headers_t hdr,
                inout metadata_t meta, inout standard_metadata_t std) {
  // ---- MAC learning ----

  // When we "learn" a digest message is sent to the controller
  // This is why we need to have a learn loop running, to read
  // the message populate the smac/dmac tables
  // Once a (mac,port) pair is learned, the smac table misses,
  // and trigger no more diggests for the same pair
  action learn() { digest<learn_t>(1, { hdr.ethernet.srcAddr, std.ingress_port }); }
  table smac {
    key            = { hdr.ethernet.srcAddr : exact; }
    actions        = { learn; NoAction; }
    size           = 4096;
    default_action = learn();
  }

  // ---- MAC forwarding ----

  // We store the flood_mgid to control it at runtime
  // Alternatively we could just use mgid 1 as the flood group
  register<bit<16>>(1) flood_mgid;

  action flood() { flood_mgid.read(std.mcast_grp, 0); }
  action forward(bit<9> port) { std.egress_spec = port; }
  table dmac {
    key            = { hdr.ethernet.dstAddr : exact; }
    actions        = { forward; flood; }
    size           = 4096;
    default_action = flood();
  }

  apply {
    smac.apply();
    dmac.apply();
  }
}

control egress(inout headers_t hdr,
               inout metadata_t meta, inout standard_metadata_t std) {
  const bit<32> PKT_INSTANCE_TYPE_REPLICATION = 5;

  apply {
    // Filter out the flooded copy that would loop back out the ingress port.
    // This is not strictly needed, as NICs would drop it in most cases, but
    // it is a nice little optimization without relying on external behaviour.
    //
    // An alternative way to achieve this would be to use metadata to flag the
    // packet as "flooded". This is essentially what the std.instance_type meta
    // does for us
    if (std.instance_type == PKT_INSTANCE_TYPE_REPLICATION &&
        std.egress_port == std.ingress_port) {
      mark_to_drop(std);
    }
  }
}

control deparse(packet_out pkt, in headers_t hdr) {
  apply {
    // A header is emitted only if it is "valid"
    pkt.emit(hdr.ethernet);
  }
}

// If we are to process L3+ we should ideally check that the packet was received
// without errors, i.e. check the IP checksum. We can skip this for mininet runs
control checksum_verify(inout headers_t hdr, inout metadata_t meta) { apply {  } }

// If we modify L3+ headers, we most likely need to update their checksums. A good
// example is the IP header. Since this program only modifies the ETH header we do
// do need to compute any checksums
control checksum_compute(inout headers_t hdr, inout metadata_t meta) { apply {  } }

V1Switch(parse(),checksum_verify(),ingress(),egress(),checksum_compute(),deparse()) main;

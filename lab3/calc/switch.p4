#include <core.p4>
#include <v1model.p4>

// In-network calculator.
// The calculator protocol is an L3 protocol: it sits directly on top of
// Ethernet with its own etherType. A request carries an opcode and two
// signed 32-bit operands. The switch executes the operation, writes the
// result into `a`, and bounces the packet back out the ingress port.
// All non-calculator traffic is forwarded like the reference L2 switch.

const bit<16> ETH_TYPE_CALC = 0x1234;
const bit<48> CALC_SWITCH_MAC = 0x000000000099; // src MAC used on responses
const bit<32> PKT_INSTANCE_TYPE_REPLICATION = 5;

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
  state start {
    pkt.extract(hdr.eth);
    transition select(hdr.eth.etherType) {
      ETH_TYPE_CALC : parse_calc;
      default       : accept;
    }
  }
  state parse_calc {
    pkt.extract(hdr.calc);
    transition accept;
  }
}

// === IMPORTANT NOTE ===
//
// There is currently a bug with the BMv2 switch P4 compiler
// When reading a signed register, and then using the result for a signed operation,
// the switch actually performs that operation as unsigned instead. To avoid it we
// use the SIGNED macro on every value read back from the register.
#define SIGNED(bits,var) ((int<bits>)(bit<bits>)var)

control calculator(inout headers_t hdr, inout metadata_t meta,
                   inout standard_metadata_t std) {

  // The single signed 32-bit memory cell. Stored as raw bits; we cast
  // through SIGNED() whenever we need signed semantics.
  register<bit<32>>(1) mem;

  bit<32> memv;   // raw register value
  int<32> old;    // signed view of mem BEFORE the operation
  bit<32> sx;     // sign mask of x    (all-ones iff x < 0)
  bit<32> sy;     // sign mask of y
  bit<32> sd;     // sign mask of x-y  (only meaningful when signs agree)
  bit<32> lt;     // all-ones iff x < y (signed, overflow-safe)

  // P4 actions cannot contain if-statements, so min/max are computed
  // branchlessly. A plain (x - y) < 0 test overflows when x and y have
  // opposite signs (e.g. INT_MIN vs INT_MAX), so we decompose:
  //   x < y  <=>  (x<0 && y>=0)  ||  (sign(x)==sign(y) && (x-y)<0)
  // as bit masks:  lt = (sx & ~sy) | (~(sx ^ sy) & sd)
  // and then select: min = (x & lt)|(y & ~lt), max = (y & lt)|(x & ~lt).

  // ------------------------- arithmetic ops --------------------------------
  action op_add() { hdr.calc.a = hdr.calc.a + hdr.calc.b; }

  action op_min() {
    sx = (bit<32>)(hdr.calc.a >> 31);
    sy = (bit<32>)(hdr.calc.b >> 31);
    sd = (bit<32>)((hdr.calc.a - hdr.calc.b) >> 31);
    lt = (sx & ~sy) | (~(sx ^ sy) & sd);
    hdr.calc.a = SIGNED(32, (((bit<32>)hdr.calc.a & lt) |
                             ((bit<32>)hdr.calc.b & ~lt)));
  }

  action op_max() {
    sx = (bit<32>)(hdr.calc.a >> 31);
    sy = (bit<32>)(hdr.calc.b >> 31);
    sd = (bit<32>)((hdr.calc.a - hdr.calc.b) >> 31);
    lt = (sx & ~sy) | (~(sx ^ sy) & sd);
    hdr.calc.a = SIGNED(32, (((bit<32>)hdr.calc.b & lt) |
                             ((bit<32>)hdr.calc.a & ~lt)));
  }

  action op_neg() { hdr.calc.a = -hdr.calc.a; }
  action op_shl() { hdr.calc.a = hdr.calc.a << 1; }
  action op_shr() { hdr.calc.a = hdr.calc.a >> 1; }  // arithmetic (signed) shift

  // -------------------------- memory ops -----------------------------------
  // Every op that writes mem returns the PREVIOUS value of mem in `a`.
  // Each action performs exactly one read-modify-write on the register.

  action op_mstore() {
    mem.read(memv, 0); old = SIGNED(32, memv);
    mem.write(0, (bit<32>)hdr.calc.a);
    hdr.calc.a = old;
  }

  action op_mload() {
    mem.read(memv, 0);
    hdr.calc.a = SIGNED(32, memv);
  }

  action op_madd() {
    mem.read(memv, 0); old = SIGNED(32, memv);
    mem.write(0, (bit<32>)(old + hdr.calc.a));
    hdr.calc.a = old;
  }

  action op_mmin() {
    mem.read(memv, 0); old = SIGNED(32, memv);
    sx = (bit<32>)(old >> 31);
    sy = (bit<32>)(hdr.calc.a >> 31);
    sd = (bit<32>)((old - hdr.calc.a) >> 31);
    lt = (sx & ~sy) | (~(sx ^ sy) & sd);
    mem.write(0, (((bit<32>)old & lt) | ((bit<32>)hdr.calc.a & ~lt)));
    hdr.calc.a = old;
  }

  action op_mmax() {
    mem.read(memv, 0); old = SIGNED(32, memv);
    sx = (bit<32>)(old >> 31);
    sy = (bit<32>)(hdr.calc.a >> 31);
    sd = (bit<32>)((old - hdr.calc.a) >> 31);
    lt = (sx & ~sy) | (~(sx ^ sy) & sd);
    mem.write(0, (((bit<32>)hdr.calc.a & lt) | ((bit<32>)old & ~lt)));
    hdr.calc.a = old;
  }

  action op_mneg() {
    mem.read(memv, 0); old = SIGNED(32, memv);
    mem.write(0, (bit<32>)(-old));
    hdr.calc.a = old;
  }

  action op_mshl() {
    mem.read(memv, 0); old = SIGNED(32, memv);
    mem.write(0, (bit<32>)(old << 1));
    hdr.calc.a = old;
  }

  action op_mshr() {
    mem.read(memv, 0); old = SIGNED(32, memv);
    mem.write(0, (bit<32>)(old >> 1));
    hdr.calc.a = old;
  }

  // ------------------------- op dispatch table ------------------------------
  table ops {
    key = { hdr.calc.op : exact; }
    actions = {
      op_add; op_min; op_max; op_neg; op_shl; op_shr;
      op_mstore; op_mload; op_madd; op_mmin; op_mmax;
      op_mneg; op_mshl; op_mshr;
      NoAction;
    }
    const entries = {
      1  : op_add();
      2  : op_min();
      3  : op_max();
      4  : op_neg();
      5  : op_shl();
      6  : op_shr();
      11 : op_mstore();
      12 : op_mload();
      13 : op_madd();
      14 : op_mmin();
      15 : op_mmax();
      16 : op_mneg();
      17 : op_mshl();
      18 : op_mshr();
    }
    default_action = NoAction();   // unknown op: echo `a` back unchanged
  }

  apply {
    ops.apply();
  }
}

control ingress(inout headers_t hdr, inout metadata_t meta,
                inout standard_metadata_t std) {
  calculator() calc;

  // Standard L2 forwarding for all non-calculator traffic
  register<bit<16>>(1) flood_mgid;

  action flood() { flood_mgid.read(std.mcast_grp, 0); }
  action forward(bit<9> port) { std.egress_spec = port; }

  table dmac {
    key            = { hdr.eth.dstAddr : exact; }
    actions        = { forward; flood; }
    size           = 4096;
    default_action = flood();
  }

  apply {
    if (hdr.calc.isValid()) {
      // Compute the result, then send it straight back to the client:
      // the forwarding decision is made here (not in the calculator
      // control) by bouncing the packet out its ingress port.
      calc.apply(hdr, meta, std);
      hdr.eth.dstAddr = hdr.eth.srcAddr;
      hdr.eth.srcAddr = CALC_SWITCH_MAC;
      std.egress_spec = std.ingress_port;
    } else {
      dmac.apply();
    }
  }
}

control egress(inout headers_t hdr, inout metadata_t meta,
               inout standard_metadata_t std) {
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
    pkt.emit(hdr.eth);
    pkt.emit(hdr.calc);
  }
}

control no_checksum(inout headers_t hdr, inout metadata_t meta) { apply {  } }

V1Switch(parse(),no_checksum(),ingress(),egress(),no_checksum(),deparse()) main;

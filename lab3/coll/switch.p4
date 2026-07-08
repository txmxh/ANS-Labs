#include <core.p4>
#include <v1model.p4>

// In-network AllReduce (SwitchML-style streaming aggregation).
//
// Protocol (must match worker.py): an L5 header on top of UDP, identified
// by UDP dst port SML_PORT. Workers split their input vector into
// CHUNK-sized packets and send them to the IP broadcast address. The
// switch aggregates each chunk in a slot; when contributions from all
// `world` workers have arrived, the aggregated chunk is multicast back
// to every worker (via the flood group).
//
// Reliability follows SwitchML's double-buffering scheme (Algorithm 2):
//  * Each window slot exists in two versions (ver 0/1). A worker uses
//    version (chunk / WINDOW) % 2, so consecutive uses of the same slot
//    alternate versions and the previous result stays available for
//    retransmission until the slot is provably no longer needed.
//  * seen0/seen1 bitmaps record which workers contributed to each
//    (slot, version); duplicates (retransmissions) are never re-added.
//  * count wraps to 0 on completion. So for a duplicate: count == 0
//    means "aggregation complete" -> unicast the stored result back;
//    count != 0 means "still aggregating" -> drop, the worker retries.
//  * A worker's contribution to (slot, v) clears its bit in (slot, 1-v),
//    which releases the other version for reuse.
//
// Pipeline discipline: every register array is accessed at most once
// per packet (a single read-modify-write on one index).

#define SML_PORT   47474   // UDP dst port identifying AllReduce traffic
#define MAX_WINDOW 128     // max supported sliding-window size (per version)
#define NSLOTS     256     // 2 * MAX_WINDOW; version-interleaved: idx = 2*slot + ver

const bit<16> ETH_TYPE_IPV4 = 0x0800;
const bit<8>  IPPROTO_UDP   = 17;
const bit<32> PKT_INSTANCE_TYPE_REPLICATION = 5;

const bit<8> SML_REQ = 0;   // worker -> switch: contribution
const bit<8> SML_RES = 1;   // switch -> worker(s): aggregated result

header ethernet_t {
  bit<48> dstAddr;
  bit<48> srcAddr;
  bit<16> etherType;
}

header ipv4_t {
  bit<4>  version;
  bit<4>  ihl;
  bit<8>  tos;
  bit<16> totalLen;
  bit<16> identification;
  bit<3>  flags;
  bit<13> fragOffset;
  bit<8>  ttl;
  bit<8>  protocol;
  bit<16> hdrChecksum;
  bit<32> srcAddr;
  bit<32> dstAddr;
}

header udp_t {
  bit<16> srcPort;
  bit<16> dstPort;
  bit<16> length;
  bit<16> checksum;
}

// AllReduce header. CHUNK = 8 values per packet.
header sml_t {
  bit<8>  flags;   // SML_REQ / SML_RES
  bit<8>  rank;    // sender's rank (0..world-1), world <= 64
  bit<16> world;   // number of workers N
  bit<16> slot;    // window slot index (0..WINDOW-1)
  bit<8>  ver;     // slot version (0/1), alternates per slot reuse
  bit<8>  pad;
  bit<32> chunk;   // global chunk id (opaque to the switch, echoed back)
  bit<32> v0;
  bit<32> v1;
  bit<32> v2;
  bit<32> v3;
  bit<32> v4;
  bit<32> v5;
  bit<32> v6;
  bit<32> v7;
}

struct headers_t {
  ethernet_t ethernet;
  ipv4_t     ipv4;
  udp_t      udp;
  sml_t      sml;
}

struct metadata_t { }

parser parse(packet_in pkt, out headers_t hdr,
             inout metadata_t meta, inout standard_metadata_t std) {
  state start {
    pkt.extract(hdr.ethernet);
    transition select(hdr.ethernet.etherType) {
      ETH_TYPE_IPV4 : parse_ipv4;
      default       : accept;
    }
  }
  state parse_ipv4 {
    pkt.extract(hdr.ipv4);
    transition select(hdr.ipv4.protocol) {
      IPPROTO_UDP : parse_udp;
      default     : accept;
    }
  }
  state parse_udp {
    pkt.extract(hdr.udp);
    transition select(hdr.udp.dstPort) {
      SML_PORT : parse_sml;
      default  : accept;
    }
  }
  state parse_sml {
    pkt.extract(hdr.sml);
    transition accept;
  }
}

// Aggregate one value into its pool register: on the FIRST contribution of
// a round (cnt == 0) the stale slot content is overwritten, otherwise the
// value is added. The running sum is also written back into the header, so
// the final contribution's packet already carries the complete result.
#define AGGREGATE(POOL, FIELD)                      \
    POOL.read(tmp, idx);                            \
    if (cnt == 0) { tmp = FIELD; }                  \
    else          { tmp = tmp + FIELD; }            \
    POOL.write(idx, tmp);                           \
    FIELD = tmp;

// Read a stored (complete) result back into the header.
#define READBACK(POOL, FIELD) POOL.read(FIELD, idx);

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

  // ---------------- AllReduce state ----------------------------------------
  // One bitmap register array per version (so each array is touched at most
  // once per packet), indexed by slot. Bit r set = worker r contributed.
  register<bit<64>>(MAX_WINDOW) seen0;
  register<bit<64>>(MAX_WINDOW) seen1;

  // Contribution counter and value pools, indexed by idx = 2*slot + ver.
  register<bit<16>>(NSLOTS) agg_count;
  register<bit<32>>(NSLOTS) pool0;
  register<bit<32>>(NSLOTS) pool1;
  register<bit<32>>(NSLOTS) pool2;
  register<bit<32>>(NSLOTS) pool3;
  register<bit<32>>(NSLOTS) pool4;
  register<bit<32>>(NSLOTS) pool5;
  register<bit<32>>(NSLOTS) pool6;
  register<bit<32>>(NSLOTS) pool7;

  apply {
    if (hdr.sml.isValid() && hdr.sml.flags == SML_REQ) {
      bit<32> slot = (bit<32>)hdr.sml.slot;
      bit<32> idx  = (slot << 1) + (bit<32>)(hdr.sml.ver & 1);
      bit<64> mask = 64w1 << hdr.sml.rank;

      bit<64> bm;
      if (hdr.sml.ver == 0) { seen0.read(bm, slot); }
      else                  { seen1.read(bm, slot); }

      bit<16> cnt;
      agg_count.read(cnt, idx);

      if ((bm & mask) == 0) {
        // ------------- new contribution from this worker -------------------
        // Record it, and release this worker's bit in the OTHER version of
        // the slot (a worker only moves on after completing the previous
        // round that used it, so the other version is safe to release).
        bit<64> obm;
        if (hdr.sml.ver == 0) {
          seen0.write(slot, bm | mask);
          seen1.read(obm, slot);
          seen1.write(slot, obm & ~mask);
        } else {
          seen1.write(slot, bm | mask);
          seen0.read(obm, slot);
          seen0.write(slot, obm & ~mask);
        }

        bit<32> tmp;
        AGGREGATE(pool0, hdr.sml.v0)
        AGGREGATE(pool1, hdr.sml.v1)
        AGGREGATE(pool2, hdr.sml.v2)
        AGGREGATE(pool3, hdr.sml.v3)
        AGGREGATE(pool4, hdr.sml.v4)
        AGGREGATE(pool5, hdr.sml.v5)
        AGGREGATE(pool6, hdr.sml.v6)
        AGGREGATE(pool7, hdr.sml.v7)

        cnt = cnt + 1;
        if (cnt == hdr.sml.world) {
          // Round complete. Count wraps to 0 ("complete" marker); the pools
          // keep the result so lost responses can be re-served. The header
          // already holds the full sums: broadcast it to all workers.
          agg_count.write(idx, 0);
          hdr.sml.flags = SML_RES;
          hdr.udp.checksum = 0;   // payload changed; 0 = "no checksum" for UDP/IPv4
          flood_mgid.read(std.mcast_grp, 0);
          log_msg("SML complete: slot={} ver={} chunk={}",
                  {hdr.sml.slot, hdr.sml.ver, hdr.sml.chunk});
        } else {
          agg_count.write(idx, cnt);
          mark_to_drop(std);
        }
      } else {
        // ------------- duplicate contribution (retransmission) -------------
        if (cnt == 0) {
          // Aggregation already complete: the result response to this worker
          // was lost. Serve the stored result back, unicast (ingress port).
          READBACK(pool0, hdr.sml.v0)
          READBACK(pool1, hdr.sml.v1)
          READBACK(pool2, hdr.sml.v2)
          READBACK(pool3, hdr.sml.v3)
          READBACK(pool4, hdr.sml.v4)
          READBACK(pool5, hdr.sml.v5)
          READBACK(pool6, hdr.sml.v6)
          READBACK(pool7, hdr.sml.v7)
          hdr.sml.flags = SML_RES;
          hdr.udp.checksum = 0;
          std.egress_spec = std.ingress_port;
          log_msg("SML re-serve: slot={} ver={} chunk={} rank={}",
                  {hdr.sml.slot, hdr.sml.ver, hdr.sml.chunk, hdr.sml.rank});
        } else {
          // Still aggregating; this contribution was already counted.
          // The worker will time out and retry until the round completes.
          mark_to_drop(std);
        }
      }
    } else {
      // AllReduce responses never re-enter the switch; everything that is
      // not an AllReduce request is normal traffic.
      dmac.apply();
    }
  }
}

control egress(inout headers_t hdr,
               inout metadata_t meta, inout standard_metadata_t std) {
  apply {
    // Filter the flooded copy that loops back out the ingress port -- but
    // NOT for AllReduce results: the last contributor needs its copy too.
    if (std.instance_type == PKT_INSTANCE_TYPE_REPLICATION &&
        std.egress_port == std.ingress_port &&
        !hdr.sml.isValid()) {
      mark_to_drop(std);
    }
  }
}

control deparse(packet_out pkt, in headers_t hdr) {
  apply {
    pkt.emit(hdr.ethernet);
    pkt.emit(hdr.ipv4);
    pkt.emit(hdr.udp);
    pkt.emit(hdr.sml);
  }
}

// We never modify any IPv4 header field, so the original IP checksum stays
// valid. The UDP checksum is set to 0 (legal for UDP over IPv4) whenever the
// payload is rewritten. No checksum computation needed.
control no_checksum(inout headers_t hdr, inout metadata_t meta) { apply {  } }

V1Switch(parse(),no_checksum(),ingress(),egress(),no_checksum(),deparse()) main;

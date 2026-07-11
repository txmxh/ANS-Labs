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

// Pseudo identity used as the SOURCE of every packet the switch originates
// (results). It must be a plain unicast address that belongs to no host:
// reflecting the request's addresses instead would produce packets that the
// workers' Linux IP stack silently rejects -- either because the source is
// the subnet broadcast (martian source), or, for the broadcast copy that
// returns to the round's last contributor, the receiver's OWN IP (spoofed).
const bit<48> SWITCH_MAC = 48w0x02534D4C00FE;  // locally administered, "SML"
const bit<32> SWITCH_IP  = 32w0x0A0000FE;      // 10.0.0.254

const bit<8> SML_REQ = 0;   // worker -> switch: contribution (also ToR -> core partial)
const bit<8> SML_RES = 1;   // switch -> worker(s): final aggregated result

// Hierarchy roles, written into cfg_is_tor by the controller.
const bit<8> ROLE_CORE = 0;
const bit<8> ROLE_TOR  = 1;

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

  // ---------------- hierarchy config (written by the controller) -----------
  // All switches run this same program; the controller tells each one who it
  // is. Each register is read at most once per packet.
  register<bit<8>>(1)  cfg_is_tor;    // ROLE_TOR at level 1, ROLE_CORE at level 2
  register<bit<16>>(1) cfg_expected;  // contributors to wait for: local workers
                                      // (ToR) or number of ToRs (core)
  register<bit<8>>(1)  cfg_rank;      // this ToR's rank at the core (0..T-1)
  register<bit<16>>(1) cfg_uplink;    // ToR's egress port towards the core
  register<bit<16>>(1) down_mgid;     // mcast group for distributing results
                                      // (ToR: worker ports; core: ToR ports)

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

  // Result packets are ORIGINATED by the switch and carry SWITCH_MAC/IP as
  // their source (see the note at the constants above). UDP ports are
  // symmetric here (both ends use SML_PORT) so they need no change.

  // Broadcast a completed result to every worker via the flood group. The
  // IP destination stays the subnet broadcast the workers sent to, which
  // every socket bound to INADDR_ANY:SML_PORT receives.
  action broadcast_result() {
    hdr.ethernet.srcAddr = SWITCH_MAC;
    hdr.ethernet.dstAddr = 48w0xFFFFFFFFFFFF;
    hdr.ipv4.srcAddr     = SWITCH_IP;
    flood_mgid.read(std.mcast_grp, 0);
  }

  // Unicast a re-served result back to the one worker that asked again.
  action reply_to_sender() {
    hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
    hdr.ethernet.srcAddr = SWITCH_MAC;
    hdr.ipv4.dstAddr     = hdr.ipv4.srcAddr;
    hdr.ipv4.srcAddr     = SWITCH_IP;
  }

  apply {
    if (hdr.sml.isValid() && hdr.sml.flags == SML_RES) {
      // A final result travelling DOWN the hierarchy (core -> ToR at a ToR's
      // uplink). Distribute it to this switch's downstream side: worker
      // ports at a ToR. (The core never receives SML_RES packets.)
      down_mgid.read(std.mcast_grp, 0);
    } else if (hdr.sml.isValid() && hdr.sml.flags == SML_REQ) {
      bit<8>  is_tor;
      bit<16> expected;
      cfg_is_tor.read(is_tor, 0);
      cfg_expected.read(expected, 0);

      bit<32> slot = (bit<32>)hdr.sml.slot;
      bit<32> idx  = (slot << 1) + (bit<32>)(hdr.sml.ver & 1);
      // Contributor id: the worker's global rank at a ToR (each worker is
      // wired to exactly one ToR, so global ranks work as bitmap bits), or
      // the sending ToR's rank at the core.
      bit<64> mask = 64w1 << hdr.sml.rank;

      bit<64> bm;
      if (hdr.sml.ver == 0) { seen0.read(bm, slot); }
      else                  { seen1.read(bm, slot); }

      bit<16> cnt;
      agg_count.read(cnt, idx);

      if ((bm & mask) == 0) {
        // ------------- new contribution from this sender -------------------
        // Record it, and release this sender's bit in the OTHER version of
        // the slot. The double-buffering invariant survives the hierarchy:
        // a sender contributes chunk c only after chunk c-WINDOW fully
        // completed end-to-end, so the other version is safe to release.
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
        if (cnt == expected) {
          // Level complete. Count wraps to 0 ("complete" marker); the pools
          // keep this level's result for loss recovery. The header already
          // holds the aggregate.
          agg_count.write(idx, 0);
          if (is_tor == ROLE_TOR) {
            // PARTIAL result: push it UP to the core as a contribution,
            // identified by this ToR's rank. Flags stay SML_REQ.
            bit<8> trank;
            bit<16> up;
            cfg_rank.read(trank, 0);
            cfg_uplink.read(up, 0);
            hdr.sml.rank = trank;
            hdr.udp.checksum = 0;   // payload changed
            std.egress_spec = (bit<9>)up;
            log_msg("SML partial up: slot={} ver={} chunk={} as rank {}",
                    {hdr.sml.slot, hdr.sml.ver, hdr.sml.chunk, trank});
          } else {
            // FINAL result: broadcast it down to all ToRs.
            hdr.sml.flags = SML_RES;
            hdr.udp.checksum = 0;
            broadcast_result();
            log_msg("SML complete: slot={} ver={} chunk={} -> broadcast",
                    {hdr.sml.slot, hdr.sml.ver, hdr.sml.chunk});
          }
        } else {
          agg_count.write(idx, cnt);
          mark_to_drop(std);
        }
      } else {
        // ------------- duplicate contribution (loss recovery) --------------
        if (cnt == 0) {
          // This level already completed (slot, ver). Serve the STORED
          // aggregate of this level back into the header...
          READBACK(pool0, hdr.sml.v0)
          READBACK(pool1, hdr.sml.v1)
          READBACK(pool2, hdr.sml.v2)
          READBACK(pool3, hdr.sml.v3)
          READBACK(pool4, hdr.sml.v4)
          READBACK(pool5, hdr.sml.v5)
          READBACK(pool6, hdr.sml.v6)
          READBACK(pool7, hdr.sml.v7)
          hdr.udp.checksum = 0;
          if (is_tor == ROLE_TOR) {
            // ...and RE-PUSH the partial up: either the original push was
            // lost (core aggregates it now) or the final result was lost on
            // its way down (core sees a duplicate and re-serves it). The
            // worker's retransmission drives recovery through both levels.
            bit<8> trank;
            bit<16> up;
            cfg_rank.read(trank, 0);
            cfg_uplink.read(up, 0);
            hdr.sml.rank = trank;
            std.egress_spec = (bit<9>)up;
            log_msg("SML re-push up: slot={} ver={} chunk={}",
                    {hdr.sml.slot, hdr.sml.ver, hdr.sml.chunk});
          } else {
            // ...and unicast the FINAL result back down the asking ToR's
            // port; that ToR redistributes it to its workers.
            hdr.sml.flags = SML_RES;
            reply_to_sender();
            std.egress_spec = std.ingress_port;
            log_msg("SML re-serve: slot={} ver={} chunk={} rank={}",
                    {hdr.sml.slot, hdr.sml.ver, hdr.sml.chunk, hdr.sml.rank});
          }
        } else {
          // Still aggregating at this level; contribution already counted.
          mark_to_drop(std);
        }
      }
    } else {
      // Everything that is not AllReduce is normal traffic.
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

control no_checksum(inout headers_t hdr, inout metadata_t meta) { apply {  } }

// Result packets get the switch's pseudo source IP written into them, which
// invalidates the IPv4 header checksum -- recompute it on the way out (for
// untouched packets this just recomputes the value they already carry). The
// UDP checksum is set to 0 (legal for UDP over IPv4) whenever the payload
// is rewritten, so it needs no computation.
control compute_checksum(inout headers_t hdr, inout metadata_t meta) {
  apply {
    update_checksum(
        hdr.ipv4.isValid(),
        { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.tos,
          hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags,
          hdr.ipv4.fragOffset, hdr.ipv4.ttl, hdr.ipv4.protocol,
          hdr.ipv4.srcAddr, hdr.ipv4.dstAddr },
        hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
  }
}

V1Switch(parse(),no_checksum(),ingress(),egress(),compute_checksum(),deparse()) main;

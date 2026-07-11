# Bonus 4.5 -- Hierarchical AllReduce (2 levels)

```
 h1 h2 --- s1 (ToR) ---\
                         s0 (core, level 2)
 h3 h4 --- s2 (ToR) ---/
```

Each ToR aggregates ONLY its local workers into a PARTIAL result and pushes
it up to the core as a contribution (SML_REQ, rank = the ToR's rank). The
core aggregates the partials of all ToRs; the FINAL result travels down as
SML_RES: broadcast to all ToRs, each ToR re-broadcasts it to its workers.
Workers are completely unchanged relative to the base task.

## How to run

```bash
sudo python network.py 2 2        # 2 ToRs x 2 workers each (defaults)
sudo python controller.py -s      # provisions ALL switches (roles + forwarding)
sudo ./run_workers.sh 4           # N = total workers = ToRs x workers-per-ToR
grep -l "all done" log/worker*.log
```

`network.py T K` builds T ToRs with K workers each; always run
`run_workers.sh` with N = T*K. Packet loss test: run each worker manually
with `--drop 0.1` as in the base task. Note (from the lab sheet): three
BMv2 switches can be heavy on some laptops.

## Design

All switches run the SAME P4 program; `controller.py -s` derives each
switch's role from the topology (has local hosts = ToR, no hosts = core)
and writes per-switch config registers: `cfg_is_tor`, `cfg_expected` (local
workers at a ToR, number of ToRs at the core), `cfg_rank` (the ToR's rank
at the core), `cfg_uplink` (port towards the core), and `down_mgid` (result
distribution group: worker ports at a ToR). Aggregation-count targets come
from `cfg_expected`, NOT from the packet's `world` field -- the right count
differs per level (2 workers at a ToR, 2 ToRs at the core, while workers
send world = 4).

The core reuses the bitmap machinery with ToR ranks as contributor bits, so
level 2 is literally the same algorithm one level up. The double-buffering
invariant survives the hierarchy: any sender (worker or ToR) contributes
chunk c only after chunk c-WINDOW completed END-TO-END, so releasing the
other slot version on a new contribution stays safe at both levels.

## Loss recovery through the hierarchy

Only workers have timers; switches stay passive (as in SwitchML). A worker
retransmits its contribution on timeout, and the duplicate propagates
recovery through both levels:

* duplicate at a ToR, local round still counting -> drop (normal dedup);
* duplicate at a ToR, local round complete -> the ToR RE-PUSHES its stored
  partial up (covers a lost ToR->core push);
* the re-pushed duplicate at the core, final still counting -> drop;
* duplicate at the core, final complete -> the core RE-SERVES the stored
  final result, unicast down the asking ToR's port, which re-broadcasts it
  to its workers (covers a lost core->ToR or ToR->worker result).

One worker timeout mechanism therefore heals loss on any of the four hops
(worker->ToR, ToR->core, core->ToR, ToR->worker).

## Normal traffic

Every switch gets tree-wide static `dmac` entries (directly attached hosts
on their port, remote hosts towards the next hop on the tree path), so
unicast traffic between any two hosts works across the hierarchy. Flooding
uses group 1 (all ports); the existing egress replication filter prevents
reflected copies, and the tree topology has no loops.

No `util/` symlink is needed: `worker.py`/`controller.py` append the parent
directory to `sys.path` (the alternative the lab sheet allows).

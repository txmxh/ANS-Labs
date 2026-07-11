# Bonus 4.4 -- More AllReduce Operators (MIN, MAX, AVG)

Standalone copy of the basic AllReduce (`../coll`) extended with operator
support. Run it exactly like the base task, from inside this directory:

```bash
sudo python network.py <N>
sudo python controller.py -s
sudo ./run_workers.sh <N>       # exercises sum, min, max AND avg
```

No `util/` symlink is needed: `worker.py`/`controller.py` append the parent
directory to `sys.path` (the alternative the lab sheet allows), so `util`
resolves to `../util`.

## What changed relative to ../coll

* The spare `pad` byte in the SML header is now `op`
  (`0 = SUM`, `1 = MIN`, `2 = MAX`).
* The switch's per-value AGGREGATE step combines according to `op`. MIN and
  MAX compare as **signed** 32-bit values (`(int<32>)` casts -- a plain
  `bit<32>` comparison would be unsigned and order negatives above
  positives). All workers of a round use the same op, since every rank
  executes the same sequence of AllReduce calls.
* **AVG is not a switch operator** (the "do all extra operators need to be
  executed by the switch?" hint): workers request SUM and floor-divide the
  result by `world` locally. Python's `//` is a true floor (also for
  negative sums), matching the expected `sum(vals) // world` semantics.
* `worker.py`'s self-test now runs `Test.test_allreduce_all` over
  sum/min/max/avg for every pattern and size.

Zero-padding of the tail chunk stays correct for MIN/MAX: every rank pads
the same positions, and those positions are never copied into the output.

Everything else (double buffering, sliding window, packet loss handling,
broadcast result delivery) is identical to the base solution and unaffected
by the operator choice.

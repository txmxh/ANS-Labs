# Task 4 -- In-Network AllReduce

## How to run

```bash
sudo python network.py <N>          # start the network
sudo python controller.py -s       # provision L2 forwarding + reset AllReduce state
./run_workers.sh <N>               # run N workers (logs under log/)
```

Always reset (`controller.py -s` or `-r`) before starting a fresh set of
workers. Running workers can then call AllReduce any number of times in a
row without further resets.

To test packet loss: `mx h1 python worker.py 0 2 --drop 0.1` (each worker).

## Protocol

L5 over UDP. Workers send to the subnet **broadcast** address (no ARP
needed) on port **47474**, which the switch intercepts; all workers listen
on that same port, so the switch can broadcast results (via the flood
multicast group) and every worker receives them. Retransmission results are
unicast out the requester's ingress port. Header (network byte order):

| flags | rank | world | slot | ver | pad | chunk id | v0..v7 |
|-------|------|-------|------|-----|-----|----------|--------|
| 1B    | 1B   | 2B    | 2B   | 1B  | 1B  | 4B       | 8x4B   |

Chunk size is 8 values, window size 8 (`CHUNK`/`WINDOW` in `worker.py`,
matching `switch.p4`). Chunk `c` maps to `slot = c % WINDOW`,
`ver = (c / WINDOW) % 2`; the chunk counter is global across AllReduce
calls so the double-buffering invariant holds between calls.

## Reliability (SwitchML Algorithm 2)

Per (slot, version): a `seen` bitmap of contributors and a `count` that
wraps to 0 on completion; pools keep the finished result. A duplicate
contribution with `count == 0` means the response was lost -> the stored
result is re-served (unicast). A worker's contribution to (slot, v) clears
its bit in (slot, 1-v), releasing the old version for reuse. Workers only
send chunk `c` after chunk `c - WINDOW` completed. Workers retransmit their
contribution on a per-chunk timeout; this single mechanism covers loss of
both requests and responses.

## Assumptions / limits

- world size <= 64 (bitmaps are `bit<64>`), window <= 128 (`MAX_WINDOW`).
- Packets from one worker are not reordered relative to each other
  (FIFO links; same assumption SwitchML makes). Packets from different
  workers / for different slots may arrive in any order.
- Every register array is accessed at most once (one RMW) per packet.

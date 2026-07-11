import argparse
import socket
import struct
import time

import os
import sys

# coll-bonus2 has no util/ symlink: make ../util importable instead
# (per the lab sheet's sys.path alternative).
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir))

from util.collectives import Collectives, Test
from util.network import get_iface, get_ip, set_drop_prob, recv, send

# ---------------- protocol constants (must match switch.p4) ------------------
SML_PORT = 47474      # UDP port the switch intercepts (and workers listen on)
CHUNK    = 8          # values per packet (v0..v7 in switch.p4)
WINDOW   = 8          # sliding-window size; must be <= MAX_WINDOW in switch.p4
FLAG_REQ = 0
FLAG_RES = 1

# flags, rank, world, slot, ver, pad, chunk-id, then CHUNK signed 32-bit values
HDR = struct.Struct("!BBHHBBI" + f"{CHUNK}i")

SOCK_TIMEOUT = 0.05   # how long a single recv blocks
RTO          = 0.2    # per-chunk retransmission timeout

S32_MASK = 0xFFFFFFFF
def s32(x):
    """Wrap a python int to signed 32-bit two's complement."""
    x &= S32_MASK
    return x - (1 << 32) if x & 0x80000000 else x


class MyCollectives(Collectives):
    def __init__(self, rank, world):
        assert WINDOW <= 128, "WINDOW must be <= MAX_WINDOW in switch.p4"
        assert 0 <= rank < world <= 64, "switch bitmaps support up to 64 workers"
        self.rank = rank
        self.world = world

        # Workers send to the subnet broadcast address so the frame reaches
        # the switch without needing ARP. The switch identifies AllReduce
        # traffic by UDP port. Completed results come back as broadcasts
        # (re-served results as unicasts), both originated from the switch's
        # pseudo identity (10.0.0.254) -- reflecting the request's addresses
        # instead would get the packets dropped by Linux as martian/spoofed
        # sources. Binding to INADDR_ANY below receives both kinds.
        self.iface = get_iface()
        ip = get_ip()
        self.bcast = ip.rsplit(".", 1)[0] + ".255"
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except (AttributeError, OSError):
            pass
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        # Pin all traffic to the switch-facing interface so the broadcast
        # egresses there rather than being resolved via a routing guess.
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                                 self.iface.encode())
        except (AttributeError, OSError):
            pass
        self.sock.bind(("", SML_PORT))
        self.sock.settimeout(SOCK_TIMEOUT)

        # GLOBAL chunk counter. It keeps increasing across AllReduce calls so
        # the slot/version double-buffering invariant holds between calls
        # (all ranks perform the same sequence of calls, so they stay in sync).
        self.gchunk = 0

    # ------------------------------------------------------------------ send
    def _send_chunk(self, gid, vals):
        slot = gid % WINDOW
        ver = (gid // WINDOW) & 1
        payload = HDR.pack(FLAG_REQ, self.rank, self.world, slot, ver, 0,
                           gid & S32_MASK, *[s32(v) for v in vals])
        send(self.sock, payload, (self.bcast, SML_PORT))

    # ------------------------------------------------------------- AllReduce
    def AllReduce(self, input: list[int], output: list[int], op: str = "sum"):
        assert len(input), "input cannot be empty"
        assert len(input) == len(output), "input and output must have the same size"

        inp = list(input)  # copy: caller may pass the same list as in and out
        n = len(inp)
        nchunks = (n + CHUNK - 1) // CHUNK
        base = self.gchunk

        def chunk_vals(c):
            v = inp[c * CHUNK:(c + 1) * CHUNK]
            return v + [0] * (CHUNK - len(v))  # pad the tail chunk with zeros

        done = [False] * nchunks
        ndone = 0
        outstanding = {}     # local chunk index -> time of last transmission
        next_c = 0

        while ndone < nchunks:
            # Fill the window. Chunk c reuses the slot of chunk c-WINDOW (with
            # the version flipped), so it may only be sent once c-WINDOW has
            # completed -- this is what makes double buffering safe. Window
            # entries complete and advance individually (no in-order needed).
            while (next_c < nchunks and len(outstanding) < WINDOW
                   and (next_c < WINDOW or done[next_c - WINDOW])):
                self._send_chunk(base + next_c, chunk_vals(next_c))
                outstanding[next_c] = time.time()
                next_c += 1

            # Receive one response (drop emulation may raise a timeout even
            # though a packet arrived -- that emulates a lost response).
            try:
                data, _ = recv(self.sock, 2048)
                if len(data) == HDR.size:
                    f = HDR.unpack(data)
                    flags, chunk_id = f[0], f[6]
                    c = chunk_id - (base & S32_MASK)
                    if flags == FLAG_RES and 0 <= c < nchunks and not done[c]:
                        lo = c * CHUNK
                        m = min(CHUNK, n - lo)
                        output[lo:lo + m] = [s32(v) for v in f[7:7 + m]]
                        done[c] = True
                        ndone += 1
                        outstanding.pop(c, None)
            except socket.timeout:
                pass

            # Retransmit stale chunks. The switch deduplicates contributions,
            # and if the round already completed it re-serves the stored
            # result, so retransmitting the contribution covers both loss of
            # the request and loss of the response.
            now = time.time()
            for c, t in list(outstanding.items()):
                if now - t > RTO:
                    self._send_chunk(base + c, chunk_vals(c))
                    outstanding[c] = now

        self.gchunk = base + nchunks

    def ReduceScatter(self, input: list[int], output: list[int]):
        raise NotImplementedError  # bonus, not attempted

    def AllGather(self, input: list[int], output: list[int]):
        raise NotImplementedError  # bonus, not attempted


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("rank", type=int)
    p.add_argument("world", type=int)
    p.add_argument("--drop", type=float, default=0.0,
                   help="emulated send/recv drop probability (e.g. 0.1)")
    p.add_argument("--seed", type=int, default=None)
    args = p.parse_args()

    if args.drop > 0:
        set_drop_prob(send=args.drop, recv=args.drop, seed=args.seed)

    coll = MyCollectives(args.rank, args.world)

    # smoke test (as provided in the template)
    data, expected = Test.data.ar_iota_rot(args.rank, args.world, 66)
    coll.AllReduce(data, data)
    print(f"expected({len(expected)}): {expected}")
    print(f"  actual({len(data)}): {data}")
    assert data == expected, "smoke test failed"

    # Many back-to-back AllReduce calls over all test patterns and a mix of
    # sizes: smaller than a chunk, exact chunk, exact window, non-multiples.
    for size in (1, 3, CHUNK, CHUNK * WINDOW, 66, 250):
        print(f"---- size {size} ----")
        Test.test_allreduce(coll, args.rank, args.world, size)

    print("all done")
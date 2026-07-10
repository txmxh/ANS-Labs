#!/usr/bin/env python3
# Minimal one-packet AllReduce connectivity probe.
# Run on a host: mx h1 python probe.py 0 1
# With world=1, ONE worker alone completes a round, so this needs no peer.
# It tells us whether a worker's UDP packet reaches the switch and returns.

import socket, struct, sys, time
from util.network import get_iface, get_ip

SML_PORT = 47474
CHUNK = 8
HDR = struct.Struct("!BBHHBBI8i")

rank  = int(sys.argv[1]) if len(sys.argv) > 1 else 0
world = int(sys.argv[2]) if len(sys.argv) > 2 else 1

iface = get_iface()
ip = get_ip()
bcast = ip.rsplit(".", 1)[0] + ".255"
print(f"[probe] iface={iface} ip={ip} bcast={bcast} rank={rank} world={world}", flush=True)

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
s.bind(("", SML_PORT))
s.settimeout(1.0)

# one chunk: values [1..8], slot 0, ver 0, chunk id 0
payload = HDR.pack(0, rank, world, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8)

for attempt in range(5):
    print(f"[probe] sending to ({bcast},{SML_PORT}) attempt {attempt}", flush=True)
    s.sendto(payload, (bcast, SML_PORT))
    try:
        data, src = s.recvfrom(2048)
        print(f"[probe] GOT {len(data)} bytes from {src}", flush=True)
        if len(data) == HDR.size:
            f = HDR.unpack(data)
            print(f"[probe]   flags={f[0]} rank={f[1]} world={f[2]} "
                  f"chunk={f[6]} vals={list(f[7:15])}", flush=True)
            if f[0] == 1:
                print("[probe] SUCCESS: switch returned an aggregated result", flush=True)
                break
    except socket.timeout:
        print("[probe] timeout, retrying...", flush=True)

print("[probe] done", flush=True)
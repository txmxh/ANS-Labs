#!/usr/bin/env python3
# Bonus 4.5 -- 2-level hierarchical AllReduce topology.
#
#   h1 h2 ... --- s1 (ToR) ---\
#                              s0 (core / level-2)
#   ...  ...  --- s2 (ToR) ---/
#
# usage: sudo python network.py [T] [K]
#   T = number of ToR switches   (default 2)
#   K = workers per ToR switch   (default 2)
# Total workers N = T*K; run them with ./run_workers.sh <T*K>.

import os
import sys

from p4utils.mininetlib.network_API import NetworkAPI

T = int(sys.argv[1]) if len(sys.argv) > 1 else 2   # ToR switches
K = int(sys.argv[2]) if len(sys.argv) > 2 else 2   # workers per ToR

log = os.path.join(os.path.abspath(os.path.dirname(__file__)), "log")
net = NetworkAPI()

# --- level-2 (core) switch: aggregates the ToRs' partial results ---
net.addP4Switch("s0")
net.setP4Source("s0", "switch.p4")

# --- level-1 (ToR) switches and their workers ---
# All switches run the SAME P4 program; the controller writes per-switch
# config registers (role, expected contributors, uplink port, ToR rank).
h = 0
for t in range(1, T + 1):
    sw = f"s{t}"
    net.addP4Switch(sw)
    net.setP4Source(sw, "switch.p4")
    net.addLink(sw, "s0")
    for _ in range(K):
        h += 1
        host = net.addHost(f"h{h}")
        net.addLink(host, sw)
        net.setIntfMac(host, sw, f"00:00:00:00:00:{h:02x}")
        net.setIntfIp(host, sw, f"10.0.0.{h}/24")

net.setLogLevel("info")
net.disableArpTables()
net.setCompiler(outdir=log)
net.enableLogAll(log_dir=log)
net.setTopologyFile(f"{log}/topology.json")
net.enablePcapDumpAll(pcap_dir=f"{log}/pcap")
net.startNetwork()
net.enableCli()

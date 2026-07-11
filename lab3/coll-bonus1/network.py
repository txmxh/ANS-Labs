#!/usr/bin/env python3

import os
import sys

from p4utils.mininetlib.network_API import NetworkAPI

N = int(sys.argv[1]) if len(sys.argv) > 1 else 2

log = os.path.join(os.path.abspath(os.path.dirname(__file__)), "log")
net = NetworkAPI()

# --- programmable switch ---
net.addP4Switch("s1")
net.setP4Source("s1", "switch.p4")

# --- workers ---
for i in range(1, N + 1):
    h = net.addHost(f"h{i}")
    net.addLink(h, "s1")
    net.setIntfMac(h, "s1", f"00:00:00:00:00:{i:02x}")
    net.setIntfIp(h, "s1", f"10.0.0.{i}/24")

net.setLogLevel("info")
net.disableArpTables()
net.setCompiler(outdir=log)
net.enableLogAll(log_dir=log)
net.setTopologyFile(f"{log}/topology.json")
net.enablePcapDumpAll(pcap_dir=f"{log}/pcap")
net.startNetwork()
net.enableCli()

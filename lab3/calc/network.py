import os
import sys

from p4utils.mininetlib.network_API import NetworkAPI

N = int(sys.argv[1]) if len(sys.argv) > 1 else 2

log = os.path.join(os.path.abspath(os.path.dirname(__file__)), "log")
net = NetworkAPI()

# --- programmable switch ---
net.addP4Switch('s1')
net.setP4Source('s1', 'switch.p4')

# --- client ---
h = net.addHost("h1")
net.addLink(h, "s1")
net.setIntfName(h, "s1", "eth0")
net.setIntfMac(h, "s1", "00:00:00:00:00:01")
net.setIntfIp(h, "s1", "10.0.0.1/24")

net.setLogLevel("info")
net.disableArpTables()
net.setCompiler(outdir=log)
net.enableLogAll(log_dir=log)
net.setTopologyFile(f"{log}/topology.json")
net.enablePcapDumpAll(pcap_dir=f"{log}/pcap")  # per-interface .pcap captures

net.startNetwork()
net.enableCli()

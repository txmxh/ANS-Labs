#!/bin/env python3

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel

class NetworkTopo(Topo):
    def build(self):
        # 1. Add Hosts (Order matters for autoSetMacs)
        # h1  -> 00:00:00:00:00:01
        h1 = self.addHost('h1', ip='10.0.1.2/24', defaultRoute='via 10.0.1.1')
        # h2  -> 00:00:00:00:00:02
        h2 = self.addHost('h2', ip='10.0.1.3/24', defaultRoute='via 10.0.1.1')
        # ser -> 00:00:00:00:00:03
        ser = self.addHost('ser', ip='10.0.2.2/24', defaultRoute='via 10.0.2.1')
        # ext -> 00:00:00:00:00:04
        ext = self.addHost('ext', ip='192.168.1.123/24', defaultRoute='via 192.168.1.1')

        # 2. Add Switches
        s1 = self.addSwitch('s1') # LAN Switch
        s2 = self.addSwitch('s2') # Server Switch
        s3 = self.addSwitch('s3') # Router

        link_opts = dict(bw=15, delay='10ms')

        # 3. Add Links
        self.addLink(h1, s1, **link_opts)
        self.addLink(h2, s1, **link_opts)
        self.addLink(ser, s2, **link_opts)

        # Router (s3) links with explicit port mapping to match your controller
        # port 1: 10.0.1.x, port 2: 10.0.2.x, port 3: 192.168.1.x
        self.addLink(s1, s3, port2=1, **link_opts)
        self.addLink(s2, s3, port2=2, **link_opts)
        self.addLink(ext, s3, port2=3, **link_opts)

def run():
    topo = NetworkTopo()
    net = Mininet(
        topo=topo,
        switch=OVSKernelSwitch,
        link=TCLink,
        controller=None,
        autoSetMacs=True
    )

    net.addController(
        'c1',
        controller=RemoteController,
        ip='127.0.0.1',
        port=6653
    )

    net.start()
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()
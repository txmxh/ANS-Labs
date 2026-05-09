#!/bin/env python3

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel


class NetworkTopo(Topo):

    def build(self):

        h1 = self.addHost('h1', ip='10.0.1.2/24', defaultRoute='via 10.0.1.1')
        h2 = self.addHost('h2', ip='10.0.1.3/24', defaultRoute='via 10.0.1.1')
        ser = self.addHost('ser', ip='10.0.2.2/24', defaultRoute='via 10.0.2.1')
        ext = self.addHost('ext', ip='192.168.1.123/24', defaultRoute='via 192.168.1.1')

        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')

        link_opts = dict(bw=15, delay='10ms')

        self.addLink(h1, s1, port1=0, port2=1, **link_opts)
        self.addLink(h2, s1, port1=0, port2=2, **link_opts)

        self.addLink(ser, s2, port1=0, port2=1, **link_opts)

        self.addLink(s1, s3, port1=3, port2=1, **link_opts)
        self.addLink(s2, s3, port1=2, port2=2, **link_opts)

        self.addLink(ext, s3, port1=0, port2=3, **link_opts)


def run():

    net = Mininet(
        topo=NetworkTopo(),
        switch=OVSKernelSwitch,
        link=TCLink,
        controller=None
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
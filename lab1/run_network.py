#!/bin/env python3

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel


class NetworkTopo(Topo):

    def build(self):

        # Hosts
        h1 = self.addHost(
            'h1',
            ip='10.0.1.2/24',
            defaultRoute='via 10.0.1.1'
        )

        h2 = self.addHost(
            'h2',
            ip='10.0.1.3/24',
            defaultRoute='via 10.0.1.1'
        )

        ser = self.addHost(
            'ser',
            ip='10.0.2.2/24',
            defaultRoute='via 10.0.2.1'
        )

        ext = self.addHost(
            'ext',
            ip='192.168.1.123/24',
            defaultRoute='via 192.168.1.1'
        )

        # Switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')

        link_opts = dict(bw=15, delay='10ms')

        # Internal LAN
        self.addLink(h1, s1, **link_opts)
        self.addLink(h2, s1, **link_opts)

        # Server LAN
        self.addLink(ser, s2, **link_opts)

        # IMPORTANT:
        # Explicit router interface numbering

        # s3-eth1 -> internal network 10.0.1.0/24
        self.addLink(s1, s3, port2=1, **link_opts)

        # s3-eth2 -> server network 10.0.2.0/24
        self.addLink(s2, s3, port2=2, **link_opts)

        # s3-eth3 -> external network 192.168.1.0/24
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


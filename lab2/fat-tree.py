"""
 Copyright (c) 2025 Computer Networks Group @ UPB

 Permission is hereby granted, free of charge, to any person obtaining a copy of
 this software and associated documentation files (the "Software"), to deal in
 the Software without restriction, including without limitation the rights to
 use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 the Software, and to permit persons to whom the Software is furnished to do so,
 subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 """

#!/usr/bin/env python3

import os
import subprocess
import time

import mininet
import mininet.clean
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.log import lg, info
from mininet.link import TCLink
from mininet.node import Node, OVSKernelSwitch, RemoteController
from mininet.topo import Topo
from mininet.util import waitListening, custom

import topo

class FattreeNet(Topo):

    def __init__(self, ft_topo):
        Topo.__init__(self)

        # Map from node object id → mininet name
        node_to_name = {}

        # Add all switches to Mininet
        for i, switch in enumerate(ft_topo.switches):
            name = f"s{i+1}"
            node_to_name[id(switch)] = name
            self.addSwitch(name)

        # Add all servers (hosts) with correct IPs
        for i, server in enumerate(ft_topo.servers):
            name = f"h{i+1}"
            node_to_name[id(server)] = name
            self.addHost(name, ip=f"{server.ip}/8")


        # Add links — use id(edge) to avoid adding same link twice
        # (each edge is shared between two nodes' edge lists)
        added_edges = set()
        all_nodes = ft_topo.switches + ft_topo.servers

        for node in all_nodes:
            for edge in node.edges:
                if id(edge) not in added_edges:
                    added_edges.add(id(edge))
                    lname = node_to_name[id(edge.lnode)]
                    rname = node_to_name[id(edge.rnode)]
                    self.addLink(lname, rname, bw=15, delay='5ms')


def make_mininet_instance(graph_topo):

    net_topo = FattreeNet(graph_topo)
    net = Mininet(topo=net_topo, controller=None, autoSetMacs=True, link=TCLink)
    net.addController('c0', controller=RemoteController,
                      ip="127.0.0.1", port=6653)
    return net


def run(graph_topo):

    # Run the Mininet CLI with a given topology
    lg.setLogLevel('info')
    # mininet.clean.cleanup()
    net = make_mininet_instance(graph_topo)

    info('*** Starting network ***\n')
    net.start()
    info('*** Running CLI ***\n')
    CLI(net)
    info('*** Stopping network ***\n')
    net.stop()
    mininet.clean.cleanup()


if __name__ == '__main__':
    ft_topo = topo.Fattree(4)
    run(ft_topo)

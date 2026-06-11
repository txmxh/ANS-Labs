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

# Class for an edge in the graph
class Edge:
    def __init__(self):
        self.lnode = None
        self.rnode = None
    
    def remove(self):
        self.lnode.edges.remove(self)
        self.rnode.edges.remove(self)
        self.lnode = None
        self.rnode = None

# Class for a node in the graph
class Node:
    def __init__(self, id, type):
        self.edges = []
        self.id = id
        self.type = type
        self.ip = None  # we'll set this during generate()

    def add_edge(self, node):
        edge = Edge()
        edge.lnode = self
        edge.rnode = node
        self.edges.append(edge)
        node.edges.append(edge)
        return edge

    def remove_edge(self, edge):
        self.edges.remove(edge)

    def is_neighbor(self, node):
        for edge in self.edges:
            if edge.lnode == node or edge.rnode == node:
                return True
        return False


class Fattree:

    def __init__(self, num_ports):
        self.servers = []
        self.switches = []
        self.generate(num_ports)

    def generate(self, num_ports):
        k = num_ports

        # ---- CORE SWITCHES ----
        # (k/2)^2 total core switches
        # IP: 10.k.j.i  (j and i go from 1 to k/2)
        core_switches = []
        switch_id = 1

        for j in range(1, k//2 + 1):
            for i in range(1, k//2 + 1):
                node = Node(switch_id, 'core')
                node.ip = f"10.{k}.{j}.{i}"
                core_switches.append(node)
                self.switches.append(node)
                switch_id += 1

        # ---- PODS ----
        # k pods, each with k/2 agg switches + k/2 edge switches + k/2*k/2 servers
        server_id = 1

        for pod in range(k):

            # ---- AGGREGATION SWITCHES ----
            # k/2 per pod
            # IP: 10.pod.(k/2 + i).1
            agg_switches = []
            for i in range(k // 2):
                node = Node(switch_id, 'agg')
                node.ip = f"10.{pod}.{k//2 + i}.1"
                agg_switches.append(node)
                self.switches.append(node)
                switch_id += 1

            # ---- EDGE SWITCHES ----
            # k/2 per pod
            # IP: 10.pod.i.1
            edge_switches = []
            for i in range(k // 2):
                node = Node(switch_id, 'edge')
                node.ip = f"10.{pod}.{i}.1"
                edge_switches.append(node)
                self.switches.append(node)
                switch_id += 1

            # ---- SERVERS ----
            # k/2 per edge switch
            # IP: 10.pod.edge_index.host  (host starts from 1)
            for edge_idx, edge_sw in enumerate(edge_switches):
                for h in range(1, k//2 + 1):
                    server = Node(server_id, 'server')
                    server.ip = f"10.{pod}.{edge_idx}.{h}"
                    self.servers.append(server)
                    server_id += 1
                    # Connect server to its edge switch
                    edge_sw.add_edge(server)

            # ---- CONNECT EDGE TO AGGREGATION ----
            # Every edge switch connects to every agg switch in same pod
            for edge_sw in edge_switches:
                for agg_sw in agg_switches:
                    edge_sw.add_edge(agg_sw)

            # ---- CONNECT AGGREGATION TO CORE ----
            # Agg switch i connects to core group i
            # core group i = core[i*(k/2)] to core[i*(k/2) + k/2 - 1]
            for i, agg_sw in enumerate(agg_switches):
                for j in range(k // 2):
                    core_idx = i * (k // 2) + j
                    agg_sw.add_edge(core_switches[core_idx])
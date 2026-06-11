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


# ---- SANITY CHECKS ----
# Run this file directly to verify the topology is correctly built:
#   python3 topo.py
if __name__ == '__main__':
    for k in [4, 6, 8]:
        ft = Fattree(k)

        expected_core = (k // 2) ** 2
        expected_agg  = k * (k // 2)
        expected_edge = k * (k // 2)
        expected_switches = expected_core + expected_agg + expected_edge
        expected_servers  = k * (k // 2) ** 2

        # Count switches by type
        core_count = sum(1 for s in ft.switches if s.type == 'core')
        agg_count  = sum(1 for s in ft.switches if s.type == 'agg')
        edge_count = sum(1 for s in ft.switches if s.type == 'edge')

        # Count unique links
        seen = set()
        for node in ft.switches + ft.servers:
            for edge in node.edges:
                seen.add(id(edge))
        total_links = len(seen)

        # Expected links:
        #   core <-> agg  : k^2 links  (each of (k/2)^2 core switches has k ports)
        #   agg  <-> edge : k*(k/2)^2 links  (each pod: k/2 agg * k/2 edge)
        #   edge <-> host : k*(k/2)^2 links  (each pod: k/2 edge * k/2 hosts)
        expected_links = (k**2) + k*(k//2)**2 + k*(k//2)**2

        # Node degree checks
        core_degree  = [len(s.edges) for s in ft.switches if s.type == 'core']
        agg_degree   = [len(s.edges) for s in ft.switches if s.type == 'agg']
        edge_degree  = [len(s.edges) for s in ft.switches if s.type == 'edge']
        server_degree = [len(s.edges) for s in ft.servers]

        print(f"\n--- k={k} ---")
        print(f"  Core switches : {core_count:3d}  (expected {expected_core})")
        print(f"  Agg  switches : {agg_count:3d}  (expected {expected_agg})")
        print(f"  Edge switches : {edge_count:3d}  (expected {expected_edge})")
        print(f"  Total switches: {len(ft.switches):3d}  (expected {expected_switches})")
        print(f"  Servers       : {len(ft.servers):3d}  (expected {expected_servers})")
        print(f"  Total links   : {total_links:3d}  (expected {expected_links})")
        print(f"  Core degree   : min={min(core_degree)}, max={max(core_degree)}  (expected {k})")
        print(f"  Agg  degree   : min={min(agg_degree)},  max={max(agg_degree)}   (expected {k})")
        print(f"  Edge degree   : min={min(edge_degree)},  max={max(edge_degree)}   (expected {k})")
        print(f"  Server degree : min={min(server_degree)}, max={max(server_degree)}  (expected 1)")

        assert core_count  == expected_core,     f"k={k}: wrong core count"
        assert agg_count   == expected_agg,      f"k={k}: wrong agg count"
        assert edge_count  == expected_edge,     f"k={k}: wrong edge count"
        assert len(ft.servers) == expected_servers, f"k={k}: wrong server count"
        assert total_links == expected_links,    f"k={k}: wrong link count"
        assert all(d == k for d in core_degree), f"k={k}: wrong core degree"
        assert all(d == k for d in agg_degree),  f"k={k}: wrong agg degree"
        assert all(d == k for d in edge_degree), f"k={k}: wrong edge degree"
        assert all(d == 1 for d in server_degree), f"k={k}: wrong server degree"
        print(f"  All assertions passed!")
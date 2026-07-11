import os
import sys

# coll-bonus2 has no util/ symlink: make ../util importable instead
# (per the lab sheet's sys.path alternative).
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir))

from util import controller

# Register arrays holding the AllReduce state in switch.p4
SML_REGISTERS = [
    "seen0", "seen1", "agg_count",
    "pool0", "pool1", "pool2", "pool3",
    "pool4", "pool5", "pool6", "pool7",
]

ROLE_CORE = 0
ROLE_TOR = 1
FLOOD_GID = 1   # all ports (normal L2 flooding)
DOWN_GID = 2    # downstream ports only (result distribution)


class HierController(controller.Client):
    """Controller for ONE switch of the 2-level hierarchy.

    Roles are derived from the topology: a switch with directly connected
    hosts is a ToR, a switch with only switch neighbors is the core. The
    controller writes the per-switch config registers (role, expected
    contributor count, uplink port, ToR rank) and installs tree-wide L2
    unicast forwarding so normal traffic works across switches.
    """

    # ------------------------------------------------------------ topology
    def _switches(self):
        return sorted(n for n in self.topo.get_p4switches())

    def _tors(self):
        return [s for s in self._switches()
                if self.topo.get_hosts_connected_to(s)]

    def _core(self):
        cores = [s for s in self._switches()
                 if not self.topo.get_hosts_connected_to(s)]
        assert len(cores) == 1, f"expected exactly one core switch, got {cores}"
        return cores[0]

    def is_tor(self):
        return bool(self.topo.get_hosts_connected_to(self.sw))

    # ------------------------------------------------------------ provision
    def reset(self):
        super().reset()
        self.del_multicast_group(DOWN_GID)
        self.register_reset("ingress.down_mgid")
        for reg in SML_REGISTERS:
            self.register_reset(f"ingress.{reg}")
        for reg in ("cfg_is_tor", "cfg_expected", "cfg_rank", "cfg_uplink"):
            self.register_reset(f"ingress.{reg}")
        print(f"[{self.sw}] cleared AllReduce + hierarchy state")

    def setup(self):
        self.reset()
        core = self._core()
        tors = self._tors()

        if self.is_tor():
            hosts = self.topo.get_hosts_connected_to(self.sw)
            host_ports = [self.topo.node_to_node_port_num(self.sw, h)
                          for h in hosts]
            uplink = self.topo.node_to_node_port_num(self.sw, core)
            rank = tors.index(self.sw)
            self.register_write("ingress.cfg_is_tor", 0, ROLE_TOR)
            self.register_write("ingress.cfg_expected", 0, len(hosts))
            self.register_write("ingress.cfg_rank", 0, rank)
            self.register_write("ingress.cfg_uplink", 0, uplink)
            # flood = all ports (hosts + uplink); down = host ports only
            self.add_multicast_group(FLOOD_GID, sorted(host_ports + [uplink]))
            self.add_multicast_group(DOWN_GID, sorted(host_ports))
            print(f"[{self.sw}] ToR rank {rank}: {len(hosts)} workers, "
                  f"uplink port {uplink}")
        else:
            tor_ports = [self.topo.node_to_node_port_num(self.sw, t)
                         for t in tors]
            self.register_write("ingress.cfg_is_tor", 0, ROLE_CORE)
            self.register_write("ingress.cfg_expected", 0, len(tors))
            # At the core, "down" and "flood" are the same: every port faces
            # a ToR. broadcast_result() uses the flood group.
            self.add_multicast_group(FLOOD_GID, sorted(tor_ports))
            self.add_multicast_group(DOWN_GID, sorted(tor_ports))
            print(f"[{self.sw}] core: aggregating {len(tors)} ToRs")

        self.register_write("ingress.flood_mgid", 0, FLOOD_GID)
        self.register_write("ingress.down_mgid", 0, DOWN_GID)
        self.setup_mac_tree()

    def setup_mac_tree(self):
        """Static dmac entries for EVERY host, via the right local port:
        directly attached hosts on their own port, everything else towards
        the next hop on the (tree) path."""
        print(f"[{self.sw}] installing tree-wide dmac entries")
        for host in sorted(self.topo.get_hosts()):
            path = self.topo.get_shortest_paths_between_nodes(self.sw, host)[0]
            next_hop = path[1]  # path[0] == self.sw
            port = self.topo.node_to_node_port_num(self.sw, next_hop)
            self.table_add("dmac", "forward",
                           [self.topo.get_host_mac(host)], [port])


if __name__ == "__main__":
    # Same CLI as the base task, but applied to EVERY switch by default:
    #   sudo python controller.py -s        # setup all switches
    #   sudo python controller.py -r        # reset all switches
    #   sudo python controller.py s1 -s     # or target one switch explicitly
    args = set(sys.argv[1:])
    explicit_sw = next((a for a in sys.argv[1:] if not a.startswith("-")), None)
    if explicit_sw:
        c = controller.App(HierController(sw=explicit_sw))
    else:
        do_setup = bool({"-s", "--setup"} & args)
        do_reset = bool({"-r", "--reset"} & args)
        first = HierController(sw="s0")
        for sw in first._switches():
            c = HierController(sw=sw)
            if do_setup:
                c.setup()
            elif do_reset:
                c.reset()

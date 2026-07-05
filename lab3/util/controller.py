#!/usr/bin/env python3
# bmv2 Thrift-based controller (p4-utils Thrift API)
#
# Constructing the client only CONNECTS — it never touches switch state.
#
# Set the switch up:
#   sudo python -i controller.py
#   >>> c.dump_table('dmac')
#
# Just inspect a running switch (no reset, no reprovision):
#   sudo python3 -i controller.py
#   >>> c.read_register('my_register', 3)
#
# Anything not wrapped here is on c.api, e.g.
#   >>> c.api.table_add('dmac', 'forward', ['00:00:0a:00:00:02'], ['2'])


import contextlib
import json
import os
import struct
import sys
import warnings

import nnpy

warnings.filterwarnings("ignore", category=FutureWarning, module="networkx")

from p4utils.utils.helper import load_topo
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI


class _Quiet:
    _ALLOW = {"table_dump", "mc_dump"}

    def __init__(self, api, owner):
        self._api = api
        self._owner = owner

    def __dir__(self):
        return sorted(set(dir(self._api)) | set(object.__dir__(self)))

    def __getattr__(self, name):
        attr = getattr(self._api, name)
        if self._owner.verbose or not callable(attr) or name in self._ALLOW:
            return attr

        def quiet(*args, **kwargs):
            with self._silenced():
                return attr(*args, **kwargs)

        return quiet

    @staticmethod
    @contextlib.contextmanager
    def _silenced():
        with open(os.devnull, "w") as devnull, contextlib.redirect_stdout(devnull):
            yield


class Client(object):
    def __init__(self, sw="s1", topo="log/topology.json", verbose=False):
        """
        Initialize a controller client for a given switch

        :param sw: Name of the switch to control
        :param topo: Path to the topology JSON file
        :param verbose: Whether to print verbose output
        """

        assert sw, "switch name must be provided"
        assert topo, "topology must be provided"

        self.sw = sw
        self.topo_json = topo if topo is not None else "log/topology.json"
        self.topo = load_topo(self.topo_json)
        self.verbose = verbose
        self.api = _Quiet(SimpleSwitchThriftAPI(self.topo.get_thrift_port(sw)), self)

    # ---------------- higher level control ---------------
    # The following functions offer high level control of
    # the reference switch. You may use them as your base.
    # They make use of the utility functions right after to
    # control P4 objects
    # -----------------------------------------------------
    def reset(self):
        print(f"[{self.sw}] resetting switch state")
        self.table_reset("dmac")
        self.table_reset("smac")
        self.del_multicast_group(1)  # del the flood group
        self.register_reset("ingress.flood_mgid")  # clear the register

    def setup(self):
        """Perform static setup of the switch"""
        self.reset()
        self.setup_flood()
        self.setup_mac()

    def dump(self):
        self.dump_multicast_groups()
        self.dump_tables()

    def setup_flood(self, flood_group_id=1):
        """Setup the flood multicast group for the topology"""
        hosts = self.topo.get_hosts_connected_to(self.sw)
        ports = [self.topo.node_to_node_port_num(self.sw, host) for host in hosts]
        self.add_multicast_group(flood_group_id, ports)
        self.register_write("ingress.flood_mgid", 0, flood_group_id)

    def setup_mac(self):
        """Setup a static MAC/port binding for the topology"""
        print(f"[{self.sw}] setting up static mac/port for topology {self.topo_json}")
        hosts = self.topo.get_hosts_connected_to(self.sw)
        ports = [self.topo.node_to_node_port_num(self.sw, host) for host in hosts]
        for host, port in zip(hosts, ports):
            self.table_add("dmac", "forward", [self.topo.get_host_mac(host)], [port])

    # -------- only relevant to the learning switch -------
    def learn_mac(self, mac, port):
        """Add the smac entry the first time a MAC is seen, always set its dmac port."""
        if not self.have_table_entry("dmac", [mac]):
            print(f"[{self.sw}] learning {mac} on port {port}")
            self.table_add("smac", "NoAction", [mac])  # first time only: stop future digests
        else:
            print(f"[{self.sw}] updating {mac} -> port {port}")
        self.table_set("dmac", "forward", [mac], [port])

    def learn(self, setup_flood=False):
        """Run the learning loop. Read digests from the dataplane and handle them"""
        sub = nnpy.Socket(nnpy.AF_SP, nnpy.SUB)
        sub.connect(self.api.client.bm_mgmt_get_info().notifications_socket)
        sub.setsockopt(nnpy.SUB, nnpy.SUB_SUBSCRIBE, b"")

        try:
            if setup_flood:
                self.setup_flood()
            print("[learning] waiting for digests...")
            while True:
                msg = sub.recv()
                # BMv2 digest message = 32-byte header, then `num` samples.
                # Header fields ('<iQiiQi'):
                #   topic (i, 4B) - message category
                #   dev   (Q, 8B) - which switch sent it
                #   ctx   (i, 4B) - pipeline context id
                #   lst   (i, 4B) - which digest/learn list (the id from digest())
                #   buf   (Q, 8B) - batch buffer id, used to ack the batch
                #   num   (i, 4B) - number of samples/entries that follow
                topic, dev, ctx, lst, buf, num = struct.unpack("<iQiiQi", msg[:32])
                if self.verbose:
                    print("[learning] new digest from", dev, "with", num, "samples")
                payload = msg[32:]
                sample_len = 8  # this is the size of the learn_t struct

                for i in range(num):
                    sample = payload[i * sample_len : (i + 1) * sample_len]
                    mac = ":".join("%02x" % b for b in sample[0:6])
                    port = struct.unpack(">H", sample[6:8])[0]
                    self.learn_mac(mac, port)
                # ACK the digest
                self.api.client.bm_learning_ack_buffer(ctx, lst, buf)

        except KeyboardInterrupt:
            print("[learning] interrupted")

    # --------------------- utilities ---------------------
    # The following functions allow for direct control of
    # P4 objects. They are wrappers of the Thrift controller
    # API mainly fixing certain bugs and/or simplifying some
    # operations.
    # -----------------------------------------------------

    # -------------------- tables -------------------------
    def have_table(self, name):
        """Check if a table with that name exists."""
        tables = self.api.get_tables()
        return name in tables or any(t.endswith("." + name) for t in tables)

    def have_table_entry(self, table, keys):
        """True if an entry matching keys exists. False if the table has no such entry,
        or the table itself doesn't exist."""
        if not self.have_table(table):
            return False
        return self.api.get_handle_from_match(table, [str(k) for k in keys]) is not None

    def table_add(self, table, action, keys, params=None):
        """Add a table entry. keys/params are lists (one item per field/arg).
        e.g. table_add("dmac", "forward", ["00:00:0a:00:00:02"], [2])"""
        keys = [str(k) for k in keys]
        params = [str(p) for p in (params or [])]
        self.api.table_add(table, action, keys, params)
        print(f"[{self.sw}] {table}: add {keys} -> {action}({params})")

    def table_modify(self, table, action, keys, params=None):
        """Modify an existing entry, matched by keys. Errors if it doesn't exist."""
        keys = [str(k) for k in keys]
        params = [str(p) for p in (params or [])]
        self.api.table_modify_match(table, action, keys, params)
        print(f"[{self.sw}] {table}: modify {keys} -> {action}({params})")

    def table_delete(self, table, keys):
        """Delete an entry, matched by keys."""
        keys = [str(k) for k in keys]
        self.api.table_delete_match(table, keys)
        print(f"[{self.sw}] {table}: delete {keys}")

    def table_set(self, table, action, keys, params=None):
        """Add the entry if missing, else modify it."""
        if not self.have_table(table):
            print(f"[{self.sw}] no table {table}")
            return
        if self.api.get_handle_from_match(table, [str(k) for k in keys]) is not None:
            self.table_modify(table, action, keys, params)
        else:
            self.table_add(table, action, keys, params)

    def table_reset(self, table):
        """Remove all entries from a table (keeps the default action)."""
        if not self.have_table(table):
            return
        self.api.table_clear(table)
        # table_clear wipes the switch but not the API's match->handle cache; drop
        # this table's cached handles so have_table_entry doesn't see ghosts.
        cache = self.api.table_entries_match_to_handle
        for tname in cache:
            if tname == table or tname.endswith("." + table):
                cache[tname].clear()
        print(f"[{self.sw}] {table}: cleared")

    def dump_table(self, name):
        """Entries currently installed in a table."""
        print(f"[{self.sw}] table {name}:")
        self.api.table_dump(name)

    def dump_tables(self):
        """Dump every table defined in the P4 program."""
        for name in sorted(self.api.get_tables()):
            self.dump_table(name)

    # -------------------- registers ----------------------
    def register_read(self, name, index=None):
        """Value of a single register index"""
        return self.api.register_read(name, index, False)

    def register_write(self, name, index, value):
        """Write a value to a single register slot."""
        assert index is not None, "index empty"
        assert value is not None, "value empty"
        self.api.register_write(name, index, value)

    def register_reset(self, name):
        """Clear all slots in a register."""
        self.api.register_reset(name)

    def dump_register(self, name, limit=10):
        values = self.register_read(name, None)
        values = values[:limit] if limit is not None else values
        extra = " ..." if len(values) > limit else ""
        print(f"[{self.sw}] register {name}: {values}{extra}")

    # ---------------- multicast groups -------------------
    def add_multicast_group(self, group_id, ports):
        """(Re)create a multicast group on the switch with exactly these ports."""
        if group_id in self.get_multicast_groups():  # ids of existing groups
            self.del_multicast_group(group_id)
        self.api.mc_mgrp_create(group_id)
        handle = self.api.mc_node_create(0, ports)
        self.api.mc_node_associate(group_id, handle)
        print(f"[{self.sw}] added multicast group {group_id} -> ports {ports}")

    def get_multicast_group(self, group_id):
        """Return the ports currently in group_id on the switch ([] if the group doesn't exist)."""
        entries = json.loads(self.api.mc_client.bm_mc_get_entries(0))
        grp = next((g for g in entries["mgrps"] if g["id"] == group_id), None)
        if grp is None:
            return []
        l1 = {h["handle"]: h["l2_handle"] for h in entries["l1_handles"]}
        l2 = {h["handle"]: h["ports"] for h in entries["l2_handles"]}
        ports = []
        for h in grp["l1_handles"]:
            ports += l2.get(l1.get(h), [])
        return sorted(set(ports))

    def del_multicast_group(self, group_id):
        """Delete a multicast group from the switch, whatever nodes it currently has."""
        entries = json.loads(self.api.mc_client.bm_mc_get_entries(0))
        handles = next((g["l1_handles"] for g in entries["mgrps"] if g["id"] == group_id), [])
        if not handles:
            print(f"[{self.sw}] no multicast group {group_id}")
            return
        for h in handles:
            self.api.mc_node_dissociate(group_id, h)
            self.api.mc_node_destroy(h)
        self.api.mc_mgrp_destroy(group_id)
        print(f"[{self.sw}] deleted multicast group {group_id} (nodes {handles})")

    def get_multicast_groups(self):
        """Return the ids of all multicast groups currently on the switch."""
        return [g["id"] for g in json.loads(self.api.mc_client.bm_mc_get_entries(0))["mgrps"]]

    def del_multicast_groups(self):
        for grp in self.get_multicast_groups():
            self.del_multicast_group(grp)

    def dump_multicast_groups(self):
        print(f"[{self.sw}] multicast groups:")
        for gid in self.get_multicast_groups():
            print("  group %d -> ports %s" % (gid, self.get_multicast_group(gid)))


# -------------------- controller app ---------------------
# This function wraps a controller object and allows
# running it as an App from your terminal. It adds
# some command line arguments and interactive mode.
# You don't have to use, but its here if you want to.
# ---------------------------------------------------------
def App(c=None):
    """Helper function to run a controller from the command line

    Execution proceeds in two phases:
        1. Provision (optional):  --reset OR --setup (setup also resets)
        2. Interact/Dump:         Interactive mode if `python -i`, or dump switch state

    Example command lines:
        -r / --reset    clean switch state
        -s / --setup    clean switch state, provision static forwarding, then dump

    Interactive use (``python -i``):
      The controller must be bound to a top-level variable. Caller must do something like :

        if __name__ == "__main__":
            c = App(Client("s1"))   # `c =` is required for -i to expose it

        Then from the python REPL, you can interact with the controller via `c`, e.g:
          >>> c.dump_tables()

    Args:
        c: A constructed Client (or subclass) instance.

    Returns:
        The same controller instance.

    Examples:
        # Provision, then land at an interactive prompt with `c` ready:
        #   sudo python3 -i controller.py --setup
        #   >>> c.dump_table("dmac")

        # Attach to a running switch to inspect it (no flags = no changes):
        #   sudo python3 -i controller.py
        #   >>> c.dump()

        # Run the learning loop (blocks until Ctrl-C):
        #   sudo python3 -i controller.py
        #   >>> c.learn()
    """
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("sw", nargs="?", default="s1", help="switch name")
    parser.add_argument("topo", nargs="?", default="log/topology.json", help="topology.json")
    setres = parser.add_mutually_exclusive_group()
    setres.add_argument("-s", "--setup", action="store_true", help="perform a one time setup")
    setres.add_argument("-r", "--reset", action="store_true", help="wipe switch state")
    parser.add_argument("-v", "--verbose", action="store_true", help="enable verbose output")
    parser.add_argument("-d", "--dump", action="store_true", help="dump switch state")
    args = parser.parse_args()

    if c is None:
        c = Client(args.sw, args.topo)

    if args.verbose:
        c.verbose = True  # -v turns prints on; without it, c keeps how it was built
    if args.setup:
        c.setup()
    elif args.reset:
        c.reset()
    if sys.flags.interactive:
        print(f"[{c.sw}] attached. 'c' is ready — try c.dump_table('dmac').")
    if args.dump:
        c.dump()
    return c

# ---------------------------------------------------------
# This file itself can be run as an app
# ---------------------------------------------------------
if __name__ == "__main__":
    c = App()


# -----------------------------------------------------------------------------
# Want to add your own logic? Make a subclass. You inherit everything the base
# controller can do (add_forwarding_entry, learning, dump_table, ...) and add
# or change only what you need.
#
# Example:
#
#   from util.controller import Client, App
#
#   class MyController(Client):
#       def __init__(self):
#           super().__init__("s1", topo="log/topology.json")
#
#       # Override default setup behavior
#       def setup(self):
#           print("Hello from my setup")
#           ...
#
#
# Run specific functions directly:
#
#   if __name__ == "__main__":
#     MyController().setup()
#
# Or run as an App with optional interactive CLI, etc:
#
#   if __name__ == "__main__":
#     c = App(MyController())
#
# -----------------------------------------------------------------------------

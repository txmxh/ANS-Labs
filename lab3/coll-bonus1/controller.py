import os
import sys

# coll-bonus1 has no util/ symlink: make ../util importable instead
# (per the lab sheet's sys.path alternative).
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir))

from util import controller

# Register arrays holding the AllReduce state in switch.p4
SML_REGISTERS = [
    "seen0", "seen1", "agg_count",
    "pool0", "pool1", "pool2", "pool3",
    "pool4", "pool5", "pool6", "pool7",
]


class CollController(controller.Client):
    """Controller for the AllReduce switch.

    The dataplane is self-contained (rank/world/slot/version all travel in
    the packet header), so the controller only has to (a) provision normal
    L2 forwarding + the flood multicast group -- the flood group doubles as
    the result-broadcast group -- and (b) reset the aggregation state.
    """

    def reset(self):
        super().reset()
        for reg in SML_REGISTERS:
            self.register_reset(f"ingress.{reg}")
        print(f"[{self.sw}] cleared AllReduce state")

    # setup() is inherited: it calls self.reset() (the override above),
    # then installs the flood multicast group and the dmac entries.


if __name__ == "__main__":
    c = controller.App(CollController())

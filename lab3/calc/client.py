import select
import time

from scapy.all import (
    ByteField,
    Ether,
    Packet,
    SignedIntField,
    bind_layers,
    conf,
    get_if_hwaddr,
)

from util.calculator import Op, Calculator, CalculatorTester
from util.network import get_iface

# Must match ETH_TYPE_CALC in switch.p4
ETH_TYPE_CALC = 0x1234


class Calc(Packet):
    """The calculator header: 1-byte opcode + two signed 32-bit operands.
    Sits directly on top of Ethernet (our own L3 protocol)."""
    name = "Calc"
    fields_desc = [
        ByteField("op", 0),
        SignedIntField("a", 0),
        SignedIntField("b", 0),
    ]


bind_layers(Ether, Calc, type=ETH_TYPE_CALC)


class MyCalculator(Calculator):
    def __init__(self, timeout=2.0, retries=3):
        self.iface = get_iface()
        self.mac = get_if_hwaddr(self.iface).lower()
        self.sock = conf.L2socket(iface=self.iface)
        self.timeout = timeout
        self.retries = retries

    def exec(self, op: Op, a: int = 0, b: int = 0):
        # Destination MAC is irrelevant: the switch intercepts calc
        # packets by etherType before any L2 lookup happens.
        req = Ether(dst="ff:ff:ff:ff:ff:ff", src=self.mac,
                    type=ETH_TYPE_CALC) / Calc(op=int(op), a=a, b=b)

        for _ in range(self.retries):
            self.sock.send(req)
            deadline = time.time() + self.timeout
            while True:
                remaining = deadline - time.time()
                if remaining <= 0:
                    break
                r, _, _ = select.select([self.sock], [], [], remaining)
                if not r:
                    break
                pkt = self.sock.recv()
                if pkt is None or Calc not in pkt:
                    continue
                # The switch swaps the MACs on responses, so a response is
                # addressed to us. This also filters out our own outgoing
                # broadcast frame, which the packet socket sees as well.
                if pkt[Ether].dst.lower() != self.mac:
                    continue
                return pkt[Calc].a

        raise TimeoutError(f"no response from switch for op={op}")


if __name__ == "__main__":
    c = MyCalculator()
    CalculatorTester().test(c)

# run with: mx h1 python client.py
# (populate the switch's L2 tables first: sudo python util/controller.py -s)

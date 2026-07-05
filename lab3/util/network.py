import fcntl
import random
import socket
import struct


def get_iface():
    """Return the name of the first non-loopback network interface.

    Scans the system's interfaces in index order and returns the first
    one that isn't the loopback device (``lo``). Inside a Mininet host
    namespace there is normally exactly one such interface (e.g.
    ``h1-eth0``), so this reliably picks the link to the switch without
    needing to hardcode the name.

    Returns:
        str: The interface name (e.g. ``"h1-eth0"``).

    Raises:
        RuntimeError: If no non-loopback interface exists.
    """
    iface = next((n for _, n in socket.if_nameindex() if n != "lo"), None)
    if iface is None:
        raise RuntimeError("no non-loopback interface found")
    return iface


def get_ip(iface=None):
    """Return the IPv4 address assigned to ``iface`` (Linux only).
    Raises:
        RuntimeError: If no IP address is assigned to ``iface``.
    """
    # https://stackoverflow.com/questions/24196932/how-can-i-get-the-ip-address-from-a-nic-network-interface-controller-in-python

    if iface is None:
        iface = get_iface()

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        return socket.inet_ntoa(
            fcntl.ioctl(
                s.fileno(),
                0x8915,  # SIOCGIFADDR
                struct.pack("256s", iface[:15].encode()),
            )[20:24]
        )
    finally:
        s.close()



_rng = random.Random()
_send_drop_prob_ = 0
_recv_drop_prob_ = 0

def set_drop_prob(send: float = 0.0, recv: float = 0.0, seed=None):
    global _send_drop_prob_, _recv_drop_prob_
    _send_drop_prob_ = send
    _recv_drop_prob_ = recv
    if seed is not None:
        _rng.seed(seed)

def send(soc, data, addr):
    """Send `data` to `addr` using socket `soc`"""
    if _send_drop_prob_ > 0 and _rng.random() < _send_drop_prob_:
        return
    soc.sendto(data, addr)

def recv(soc, nbytes):
    res = soc.recvfrom(nbytes)
    if _recv_drop_prob_ > 0 and _rng.random() < _recv_drop_prob_:
        raise socket.timeout
    return res

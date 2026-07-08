from util import controller


class MyController(controller.Client):
    """Controller for the ARP-proxy switch.

    On top of the standard L2 setup (flood group + dmac entries) it
    installs one arp_tbl entry per directly connected host, mapping
    the host's IP -> its MAC, so the dataplane can answer ARP
    requests on the hosts' behalf.
    """

    def setup_arp(self):
        hosts = self.topo.get_hosts_connected_to(self.sw)
        for host in hosts:
            ip = self.topo.get_host_ip(host).split("/")[0]  # strip prefix len if present
            mac = self.topo.get_host_mac(host)
            self.table_add("arp_tbl", "arp_reply", [ip], [mac])

    def setup(self):
        super().setup()      # reset + flood group + dmac entries
        self.setup_arp()

    def reset(self):
        super().reset()
        self.table_reset("arp_tbl")


if __name__ == "__main__":
    c = controller.App(MyController())

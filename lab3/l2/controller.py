from util import controller


class MyController(controller.Client):
    def __init__(self):
        super().__init__("s1", topo="log/topology.json")
        print("Hello from MyController")


if __name__ == "__main__":
    c = controller.App(MyController())


# # v1
# if __name__ == "__main__":
#     c = MyController()
#     c.one_time_setup()

# # v2
# if __name__ == "__main__":
#     c = controller.ControllerClient("s1", verbose=False)
#     c.reset()

#     topo = load_topo("log/topology.json")
#     hosts = topo.get_hosts_connected_to("s1")
#     ports = [topo.node_to_node_port_num("s1", h) for h in hosts]

#     for host,port in zip(hosts, ports):
#       c.add_forwarding_entry(topo.get_host_mac(host), port)

#     c.add_multicast_group(1, ports)

# # v3
# if __name__ == "__main__":
#   c = controller.app(MyController)
#   >>> c.one_time_setup()

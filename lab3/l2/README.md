# A simple L2 switch implementation and its controller

Please study the dataplane P4 code and the controller Python code. 
All later tasks will require **at least** the behaviour of this switch. You are free to copy it and modify it (and its controller) as you please.

## Quick run

Start a single rack (start topology) mininet network with 2 hosts:

```bash
sudo python network.py
```

In the mininet CLI run `pingall`. It should fail because the switch does not yet know how to forward packets. We need to populate its tables.

In a separate terminal run:
```
sudo python util/controller.py -s
```
This will perform a one time setup. Now `pingall` should succeed.

## Understanding and extending the code

Inspect the mininet code in `network.py`. You will notice a slightly different API that the standard Mininet code. 
That is because we are making use of the [p4utils](https://github.com/nsg-ethz/p4-utils) framework. p4utils allows us to easily run P4 switches in Mininet and includes several other utilities.

We provide a `network.py` for all tasks of this lab, that you generally don't have to change. If you do want to change something check p4utils' [NetworkAPI](https://github.com/nsg-ethz/p4-utils/blob/master/p4utils/mininetlib/network_API.py) 

A useful utility is the `mx` tool, which allows us to execute commands on mininet nodes from outside mininet.
For example, while mininet is running open a new terminal and run `mx h1 ifconfig`. You should see something like this:

```text
h1-eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 9500
        inet 10.0.0.1  netmask 255.255.255.0  broadcast 10.0.0.255
        ether 00:00:00:00:00:01  txqueuelen 1000  (Ethernet)
...
```

#### Log files

After starting mininet you will notice a `log` directory. It contains several files, but the most useful ones are:

- `log/topology.json`: Contains topology info. Very usefull for static/one-time setups like the one we did above. You can use p4utils' [NetworkGraph API](https://github.com/nsg-ethz/p4-utils/blob/83b118bbae530b31cc74e7fa32f9174f7c0a1184/p4utils/utils/topology.py#L62) to query that file. In fact, our `util/controller.py` already uses it (see `setup_flood` and `setup_mac`)
- `log/p4s.s1.log`: This is the P4 switch's runtime log. It contains information about every packet the switch receives and sends as well as the code it executes on it. This is the most important tool for debugging your P4 code. It is also possible to log things to that file yourself using the [`log_msg`](https://github.com/p4lang/p4c/blob/d7b257630f18eb1444de825bb791082ff8fb816a/p4include/v1model.p4#L710) extern.
- `log/pcap/*`: When your network does `net.enablePcapDumpAll()` (all do), this directory contains 2 `.pcap` files for every port on the switch. One for the incoming packets and one for outgoing, on that same port. If you are using `vscode` you can install the [pcapviewer extension](https://marketplace.visualstudio.com/items?itemName=sankooc.pcapviewer) to read those files conveniently in your editor. Otherwise, you can always use Wireshark.
- `log/switch.p4i`: This is the preprocessed P4 program that goes into the P4 compiler. This is only useful if your uses macros and you want to validate that they work as expected.

#### P4 reference switch

The switch program we provide, and all switches you will build in this lab are based on the `v1model` architecture. This is one of the P4 architectures that the [p4lang/behavioral-model](https://github.com/p4lang/behavioral-model) family of software switches support. Your P4 program includes 2 files:

- [core.p4](https://github.com/p4lang/p4c/blob/main/p4include/core.p4): Core P4 language constructs
- [v1model.p4](https://github.com/p4lang/p4c/blob/main/p4include/v1model.p4): Constructs available only in the `v1model` architecture

Anything on those two files is available to your P4 programs and you are free to use.


The `l2/switch.p4` is a simple switch that does forwarding based on a destination mac. Inspect the code and locate the `dmac` table. This single table controls the output port given a destination mac address. We run the controller once above to perform a one-time setup, but its possible to update that table at runtime if you wish (more of that below). 

Note that `l2/switch.p4` is **not** a learning switch. I.e. someone has to give it the `mac -> port` mapping.
If you are interested in P4 learning switch, we also provide one in `l2/switch_learning.p4`. This switch uses a second table `smac` that tracks the `source_mac,port` pairs we know. If there is a hit, nothing happens; we know about this pair. If there is missed a `digest` message is sent to the controller to "learn" the `source_mac,port` pair. In both cases we end up to the `dmac` table to decide the output port.

The source code of both switches contains several comments on what different P4 structures do. We suggest you check them.

#### P4 switch controller

P4 switches can be controlled in several ways and with multiple APIs.
For your convenience we have prepared a controller that gives you most of the tools you will need throughout the lab.

You've already seen how to run a one-time setup with the `-s` flag. You can also use the `-d` flag to dump the current switch state, or `-r` to reset it. 

> The switch keeps its state — tables, multicast groups, registers — even if you restart the controller. Use `-r` (or `c.reset()`) to get a clean slate.


But you can also run the controller interactively:

```bash
$ sudo python -i util/controller.py
[s1] attached. 'c' is ready — try c.dump_table('dmac').
>>> 
```

> If a command seems to silently do nothing, set `c.verbose = True` (or start with `Client(verbose=True)`) — by default the controller mutes the underlying API's output (its too noisy), including some error messages (exceptions still throw).


Inside this python CLI you have a controller client instance `c` available. If you would like for example
to add something to the `dmac` table, you can do:

```bash
>>> c.table_set("dmac", "forward", ["00:00:00:00:00:16"], [16])
[s1] dmac: add ['00:00:00:00:00:16'] -> forward(['16'])
```

You can now dump the table and see:

```bash
>>> c.dump_table("dmac")
[s1] table dmac:
==========
TABLE ENTRIES
**********
Dumping entry 0x0
Match key:
* ethernet.dstAddr    : EXACT     000000000001
Action entry: ingress.forward - 01
**********
Dumping entry 0x1
Match key:
* ethernet.dstAddr    : EXACT     000000000002
Action entry: ingress.forward - 02
**********
Dumping entry 0x2
Match key:
* ethernet.dstAddr    : EXACT     000000000016
Action entry: ingress.forward - 10
==========
Dumping default entry
Action entry: ingress.flood - 
==========
```

You can also control P4 register values. Our reference switch uses a register for the dataplane to read the multicast group id for flooding (instead of assuming `1`). Try:

```bash
>>> c.register_read("flood_mgid", 0)
1
>>> c.register_write("flood_mgid", 0, 42)
>>> c.register_read("flood_mgid", 0)
42
```

> Note that if you just modify the `flood_mgid` register your program will stop working. That is because you need to also register the multicast group with the switch. This is what the `add_multicast_group(group_id, ports)` does.

Most of what you'll do at runtime is one of three things: write table entries, read/write registers, or manage multicast groups. The controller wraps all of them. When you add your own tables and registers in later tasks, you address them by name the same way.

**About addressing P4 objects**

Notice how we query the P4 objects we want to control by name. In general, if that name is unique the operation should succeed. If in doubt, or you have duplicates, you should use the full path. E.g.
`c.dump_table("ingress.dmac")` or `c.register_read("ingress.flood_mgid")`. 
Moreover, notice how `ingress` is the name of the ingress `control` and not the name of some instance of it. 
In P4, if only a single instance of a control exists, you can use the control block's name to reference that instance. So `ingress` here refers to the `ingress` instance passed to the `V1Switch` constructor at line 89.

A similar thing exists for dataplane code as well. If you have something `control mycontrol { ... }`, you do not have to instantiate it just to call `apply()` on it. You can just do `mycontrol.apply(...)`


#### Extending the controller

The controller we provide handles most things you will need. However you will inevitably need to extend it a bit.
For instance, Task 1 asks you for ARP support. We cannot know how you are going to call your ARP table, or any other tables you may add. Thus you will need to program control for those tables yourself.

The easiest thing to do is subclass the controller. For instance if you would like to do a one-time setup, you can do something like this:

```python
from util import controller
class MyController(controller.Client):
    def my_task_specific_setup():
        self.table_add( ... )
        ...

    def setup(self):        # override parent setup
        super().setup() # run controller.Client.setup() if you need to
        self.my_task_specific_setup()

    # You probably want something similar for reset()/dump()
```


Note that for `super().setup()` to do anything, you need to be using the same program as the base (e.g. the `dmac` table is available and so on)

Now you can run YOUR controller as an app:

```python
if __name__ == "__main__":
    controller.App(MyController())
```

Besides being a controller library and app for the reference switch, `util/controller.py` also provides utilities to directly control P4 objects in your program. These utilities are wrappers of the Thift controller API (one of many) and they exist in order to simplify certain operations as well as fix some buggy behaviour of that API. It _is_ possible to solve all Tasks using only the utilities in `util/controller.py`. However, should you need something extra, you can find the full Thrift API here: 

- `https://github.com/nsg-ethz/p4-utils/blob/master/p4utils/utils/thrift_API.py`

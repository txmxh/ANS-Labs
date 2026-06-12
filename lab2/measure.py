#!/usr/bin/env python3

import time
import re
from mininet.log import setLogLevel, info
from mininet.clean import cleanup
import fat_tree
import topo

def run_experiment():
    setLogLevel('info')
    
    # 1. Initialize Topology
    ft_topo = topo.Fattree(4)
    net = fat_tree.make_mininet_instance(ft_topo)
    
    info('*** Starting network ***\n')
    net.start()
    
    # Give the controller time to push all routes
    info('*** Waiting 10 seconds for flow rules to settle... ***\n')
    time.sleep(10)
    
    # 2. Select Hosts (Pod 0 sending to Pod 3)
    # Using specific Mininet names based on your topo.py generation
    # Pod 0: h1, h2, h3, h4
    # Pod 3: h13, h14, h15, h16
    clients = [net.get('h1'), net.get('h2'), net.get('h3'), net.get('h4')]
    servers = [net.get('h13'), net.get('h14'), net.get('h15'), net.get('h16')]
    
    # 3. Start iperf servers in the background
    info('*** Starting iperf servers in Pod 3 ***\n')
    for server in servers:
        server.cmd('iperf -s -p 5001 &')
        
    # 4. Start parallel iperf clients in Pod 0
    info('*** Starting parallel iperf clients in Pod 0 ***\n')
    popens = {}
    for i, client in enumerate(clients):
        server_ip = servers[i].IP()
        # Run for 15 seconds, reporting in Mbps
        cmd = f'iperf -c {server_ip} -p 5001 -t 15 -f m'
        popens[client] = client.popen(cmd)
        
    # 5. Collect Results
    info('*** Waiting for tests to complete... ***\n')
    total_throughput = 0.0
    
    for client, process in popens.items():
        out, err = process.communicate()
        # Parse the output to extract the bandwidth (Mbits/sec)
        match = re.search(r'(\d+(\.\d+)?)\s+Mbits/sec', out.decode('utf-8'))
        if match:
            bw = float(match.group(1))
            info(f'{client.name} -> {servers[clients.index(client)].name}: {bw} Mbps\n')
            total_throughput += bw
            
    info(f'\n*** TOTAL AGGREGATE THROUGHPUT: {total_throughput:.2f} Mbps ***\n')
    
    info('*** Stopping network ***\n')
    net.stop()
    cleanup()

if __name__ == '__main__':
    cleanup()
    run_experiment()
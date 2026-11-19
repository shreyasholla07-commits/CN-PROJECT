#!/usr/bin/env python3
"""Star topology: s1 with h1 (server), h2 & h4 (normal clients), h3 (attacker)."""
from functools import partial
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.topo import SingleSwitchTopo
from mininet.cli import CLI
from mininet.log import setLogLevel

if __name__ == '__main__':
    setLogLevel('info')
    net = Mininet(topo=SingleSwitchTopo(4), switch=partial(OVSSwitch, protocols='OpenFlow13'),
                  controller=None, autoSetMacs=True)
    net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)
    net.start()
    net.get('h1').cmd('python3 tcp_server.py 80 > /tmp/h1_server.log 2>&1 &')
    CLI(net)
    net.get('h1').cmd('pkill -f tcp_server.py')
    net.stop()

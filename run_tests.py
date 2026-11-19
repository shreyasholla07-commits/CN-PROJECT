#!/usr/bin/env python3
"""Automated system tests. Start the controller FIRST (fresh), in another terminal:
   BLOCK_TIME=15 ryu-manager dynamic_blocker.py
Then:  sudo python3 run_tests.py"""
import os, re, time, csv
from functools import partial
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.topo import SingleSwitchTopo
from mininet.log import setLogLevel

BLOCK_TIME = int(os.environ.get('BLOCK_TIME', 15))
LOG = os.environ.get('BLOCK_LOG', 'logs/blocker_events.csv')
CWD = os.getcwd()
results = []

def record(tid, name, ok, detail=''):
    results.append((tid, name, ok))
    print("[%s] %-4s %-55s %s" % ('PASS' if ok else 'FAIL', tid, name, detail))

def client(h, ip, n, gap, tmo=1.0):
    out = h.cmd('python3 %s/client.py %s 80 %d %s %s' % (CWD, ip, n, gap, tmo))
    m = re.search(r'SUCCESS=(\d+) FAIL=(\d+)', out)
    return (int(m.group(1)), int(m.group(2))) if m else (0, 0)

def log_rows():
    with open(LOG) as f:
        return list(csv.DictReader(f))

if __name__ == '__main__':
    setLogLevel('warning')
    net = Mininet(topo=SingleSwitchTopo(4), switch=partial(OVSSwitch, protocols='OpenFlow13'),
                  controller=None, autoSetMacs=True)
    net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)
    net.start(); time.sleep(3)
    h1, h2, h3, h4 = [net.get('h%d' % i) for i in range(1, 5)]
    s1 = net.get('s1')
    h1.cmd('python3 %s/tcp_server.py 80 > /tmp/srv.log 2>&1 &' % CWD); time.sleep(1)
    dump = lambda: s1.cmd('ovs-ofctl -O OpenFlow13 dump-flows s1')

    loss = net.pingAll(timeout=2)
    record('TC01', 'Basic connectivity (pingall)', loss == 0, 'loss=%s%%' % loss)

    ok, fail = client(h2, '10.0.0.1', 10, 0.5)
    record('TC02', 'Normal client (10 conns @2/s) all succeed', ok == 10 and fail == 0, 'ok=%d fail=%d' % (ok, fail))
    record('TC03', 'Normal client NOT blocked', 'nw_src=10.0.0.2' not in dump() or 'priority=100,ip,nw_src=10.0.0.2' not in dump())

    ok, fail = client(h4, '10.0.0.1', 15, 0.1)
    record('TC04', 'Below threshold (15 conns/1.5s) NOT blocked', 'priority=100,ip,nw_src=10.0.0.4' not in dump(), 'ok=%d fail=%d' % (ok, fail))

    time.sleep(6)   # let the 5s window empty
    ok, fail = client(h3, '10.0.0.1', 40, 0.02, 0.2)
    record('TC05', 'Attacker (50 conns/s) detected & DROP rule installed',
           'priority=100,ip,nw_src=10.0.0.3' in dump(), 'ok=%d fail=%d' % (ok, fail))
    record('TC06', 'Some attacker connections failed after block', fail > 0)
    ok, fail = client(h3, '10.0.0.1', 5, 0.1, 0.5)
    record('TC07', 'Blocked attacker cannot connect', ok == 0, 'ok=%d fail=%d' % (ok, fail))
    ok, fail = client(h2, '10.0.0.1', 5, 0.2)
    record('TC08', 'Legit host unaffected while attacker blocked', ok == 5, 'ok=%d fail=%d' % (ok, fail))
    rows = log_rows()
    record('TC09', 'BLOCK event logged for 10.0.0.3',
           any(r['event'] == 'BLOCK' and r['ip'] == '10.0.0.3' for r in rows))
    record('TC10', 'Only attacker is in blocklist',
           {r['ip'] for r in rows if r['event'] == 'BLOCK'} == {'10.0.0.3'})

    time.sleep(BLOCK_TIME + 3)
    record('TC11', 'Block rule auto-removed after timeout', 'priority=100,ip,nw_src=10.0.0.3' not in dump())
    ok, fail = client(h3, '10.0.0.1', 3, 0.5)
    record('TC12', 'Host can connect again after unblock', ok == 3, 'ok=%d fail=%d' % (ok, fail))
    record('TC13', 'UNBLOCK event logged',
           any(r['event'] == 'UNBLOCK' and r['ip'] == '10.0.0.3' for r in log_rows()))

    print("\nSUMMARY: %d/%d passed" % (sum(1 for r in results if r[2]), len(results)))
    h1.cmd('pkill -f tcp_server.py'); net.stop()

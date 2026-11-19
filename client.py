#!/usr/bin/env python3
"""TCP traffic generator. usage: client.py <ip> <port> <count> <interval_s> [timeout_s]
Normal client: small interval-rate. Attacker: tiny interval (e.g. 0.02)."""
import socket, sys, time
ip, port, n, gap = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), float(sys.argv[4])
tmo = float(sys.argv[5]) if len(sys.argv) > 5 else 1.0
ok = fail = 0
for _ in range(n):
    try:
        s = socket.create_connection((ip, port), timeout=tmo)
        s.sendall(b'hello'); s.recv(16); s.close(); ok += 1
    except OSError:
        fail += 1
    time.sleep(gap)
print("SUCCESS=%d FAIL=%d" % (ok, fail))

#!/usr/bin/env python3
"""Simple multi-threaded TCP server: replies OK and closes."""
import socket, sys, threading

def handle(c):
    try:
        c.recv(64); c.sendall(b'OK')
    except OSError:
        pass
    finally:
        c.close()

port = int(sys.argv[1]) if len(sys.argv) > 1 else 80
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', port)); s.listen(256)
while True:
    c, _ = s.accept()
    threading.Thread(target=handle, args=(c,), daemon=True).start()

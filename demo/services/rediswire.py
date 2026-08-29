"""Tiny RESP (Redis wire protocol) client using only the stdlib.

One connection per command, deliberately: the demo wants to exercise real
TCP connection lifecycles for Atlas to observe, not connection pooling.
"""
import socket


def command(host, *args, port=6379, timeout=3.0):
    payload = b"*%d\r\n" % len(args)
    for a in args:
        data = a.encode() if isinstance(a, str) else a
        payload += b"$%d\r\n%s\r\n" % (len(data), data)
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.sendall(payload)
        return s.recv(4096).decode(errors="replace").strip()

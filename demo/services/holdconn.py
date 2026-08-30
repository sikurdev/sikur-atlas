"""Demo hold-connection client: opens one Redis connection, speaks a
single PING, then holds the socket open forever without sending another
byte. Started before Atlas in the e2e, this is the connection the
startup seed must discover from the kernel's socket tables alone — no
replacement traffic ever happens on it."""
import socket
import time

HOST = "cache"

while True:
    try:
        s = socket.create_connection((HOST, 6379), timeout=5)
        break
    except OSError:
        time.sleep(0.5)

s.sendall(b"PING\r\n")
resp = s.recv(64)
print("holdconn: connected,", resp, flush=True)
s.settimeout(None)
while True:
    time.sleep(3600)

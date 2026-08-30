"""Demo orders service: answers HTTP, calls inventory over HTTP and the
cache over the Redis protocol on every request."""
import json
import os
import sys
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rediswire

CACHE_HOST = os.environ.get("CACHE_HOST", "cache")
INVENTORY_URL = os.environ.get("INVENTORY_URL", "http://inventory:8000/stock")
REPORTS_SOCK = os.environ.get("REPORTS_SOCK", "/sockets/reports.sock")


def tally_report():
    """One request over the shared AF_UNIX socket (real IPC edge)."""
    import socket
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(2)
        s.connect(REPORTS_SOCK)
        s.sendall(b"tally\n")
        return s.recv(256).decode(errors="replace")


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        # The report tally is independent of inventory: the IPC edge
        # must keep carrying traffic even while a TCP dependency is
        # down (that outage is part of the demo's story).
        try:
            report = tally_report()
        except OSError:
            report = "unavailable"
        try:
            with urllib.request.urlopen(INVENTORY_URL, timeout=3) as r:
                stock = json.load(r)
            rediswire.command(CACHE_HOST, "INCR", "orders:served")
            served = rediswire.command(CACHE_HOST, "GET", "orders:served")
            body = json.dumps({
                "service": "orders",
                "stock": stock,
                "served": served,
                "report": report,
            }).encode()
            status = 200
        except OSError as exc:
            body = json.dumps({
                "service": "orders",
                "error": str(exc),
                "report": report,
            }).encode()
            status = 502
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    print("orders listening on :8000", flush=True)
    ThreadingHTTPServer(("0.0.0.0", 8000), Handler).serve_forever()

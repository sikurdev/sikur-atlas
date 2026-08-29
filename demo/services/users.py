"""Demo users service: answers HTTP, touches the cache on every request.

It also attempts one connection per request to a deliberately wrong
cache port (6380 — nothing listens there). The kernel refuses it with an
RST, giving Atlas a live, honest failed-connection signal to display.
"""
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rediswire

CACHE_HOST = os.environ.get("CACHE_HOST", "cache")
BROKEN_PORT = int(os.environ.get("BROKEN_CACHE_PORT", "6380"))


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/stress"):
            return self.do_stress()
        try:
            rediswire.command(CACHE_HOST, "PING", port=BROKEN_PORT, timeout=0.5)
        except OSError:
            pass  # expected: connection refused
        try:
            rediswire.command(CACHE_HOST, "INCR", "users:served")
            served = rediswire.command(CACHE_HOST, "GET", "users:served")
            body = json.dumps({"service": "users", "served": served}).encode()
            status = 200
        except OSError as exc:
            body = json.dumps({"service": "users", "error": str(exc)}).encode()
            status = 502
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_stress(self):
        """Deliberate memory-pressure episode: allocate ?mb= for ?sec=
        seconds, in steps so resource sampling can observe the climb.
        With the compose memory limit, a large enough mb gets this
        container OOM-killed — on purpose."""
        import time
        from urllib.parse import parse_qs, urlparse

        q = parse_qs(urlparse(self.path).query)
        mb = int(q.get("mb", ["100"])[0])
        sec = float(q.get("sec", ["10"])[0])
        chunks = []
        step = 20
        for _ in range(0, mb, step):
            blob = bytearray(step * 1024 * 1024)
            for i in range(0, len(blob), 4096):
                blob[i] = 1  # commit the pages
            chunks.append(blob)
            time.sleep(0.3)
        time.sleep(sec)
        del chunks
        body = json.dumps({"service": "users", "stressed_mb": mb}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    print("users listening on :8000", flush=True)
    ThreadingHTTPServer(("0.0.0.0", 8000), Handler).serve_forever()

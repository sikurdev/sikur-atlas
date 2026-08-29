"""Demo users service: answers HTTP, touches the cache on every request."""
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rediswire

CACHE_HOST = os.environ.get("CACHE_HOST", "cache")


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
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

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    print("users listening on :8000", flush=True)
    ThreadingHTTPServer(("0.0.0.0", 8000), Handler).serve_forever()

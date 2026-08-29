"""Demo inventory service: static stock answers."""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STOCK = {"widgets": 41, "sprockets": 128, "flanges": 7}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps(STOCK).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    print("inventory listening on :8000", flush=True)
    ThreadingHTTPServer(("0.0.0.0", 8000), Handler).serve_forever()

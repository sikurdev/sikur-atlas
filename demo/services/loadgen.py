"""Demo load generator: keeps a steady trickle of requests flowing
through the gateway so Atlas has live traffic to observe."""
import os
import time
import urllib.request

GATEWAY = os.environ.get("GATEWAY_URL", "http://gateway:8080")
INTERVAL = float(os.environ.get("LOADGEN_INTERVAL", "0.4"))
PATHS = ["/orders", "/users"]

if __name__ == "__main__":
    print(f"loadgen hitting {GATEWAY} every {INTERVAL}s", flush=True)
    i = 0
    while True:
        path = PATHS[i % len(PATHS)]
        i += 1
        try:
            with urllib.request.urlopen(GATEWAY + path, timeout=5) as r:
                r.read()
        except OSError as exc:
            print(f"{path}: {exc}", flush=True)
        time.sleep(INTERVAL)

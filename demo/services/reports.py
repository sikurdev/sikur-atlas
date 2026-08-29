"""Demo reports service: listens on an AF_UNIX stream socket shared with
the orders service through a volume. Exists so Atlas has a real
unix-domain dependency to discover."""
import json
import os
import socket
import threading

SOCK = os.environ.get("REPORTS_SOCK", "/sockets/reports.sock")

count = 0
lock = threading.Lock()


def handle(conn):
    global count
    try:
        conn.recv(256)
        with lock:
            count += 1
            n = count
        conn.sendall(json.dumps({"service": "reports", "tallied": n}).encode())
    except OSError:
        pass
    finally:
        conn.close()


if __name__ == "__main__":
    os.makedirs(os.path.dirname(SOCK), exist_ok=True)
    try:
        os.unlink(SOCK)
    except FileNotFoundError:
        pass
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(SOCK)
    os.chmod(SOCK, 0o777)
    srv.listen(16)
    print(f"reports listening on {SOCK}", flush=True)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()

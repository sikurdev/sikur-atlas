#!/usr/bin/env bash
# End-to-end check: build everything, establish real connections BEFORE
# the agent starts (startup-state seeding), run the agent with real
# eBPF, run the demo workload, stage two deterministic incidents (an OOM
# kill and a dependency stop), and assert live discovery, health
# signals, Replay, Compare, the Incident Lens, restart survival and seed
# reconciliation — all against the real kernel. Requires Linux, docker
# and sudo.
set -euo pipefail
cd "$(dirname "$0")/.."

BASE_URL="http://127.0.0.1:7171"
AGENT_LOG="$(mktemp /tmp/atlas-e2e-XXXX.log)"
DB_DIR="$(mktemp -d /tmp/atlas-e2e-db-XXXX)"
SUDO_PID=""
HOST_HOLD_PID=""

cleanup() {
    status=$?
    set +e
    echo "== agent log =="
    cat "$AGENT_LOG" || true
    if [ -n "$HOST_HOLD_PID" ]; then
        kill "$HOST_HOLD_PID" 2>/dev/null
    fi
    if [ -n "$SUDO_PID" ]; then
        sudo kill "$SUDO_PID" 2>/dev/null
        sleep 1
    fi
    docker compose -f demo/docker-compose.yml down -v --timeout 5 >/dev/null 2>&1
    sudo rm -rf "$DB_DIR"
    exit $status
}
trap cleanup EXIT

start_agent() {
    sudo ./bin/atlas --listen 127.0.0.1:7171 --db "$DB_DIR/history.db" >>"$AGENT_LOG" 2>&1 &
    SUDO_PID=$!
    for i in $(seq 1 20); do
        if curl -fsS "$BASE_URL/api/meta" >/dev/null 2>&1; then
            return 0
        fi
        if ! kill -0 "$SUDO_PID" 2>/dev/null; then
            echo "agent exited during startup"
            return 1
        fi
        sleep 1
    done
    echo "agent API never came up"
    return 1
}

stop_agent() {
    sudo kill "$SUDO_PID"
    for i in $(seq 1 10); do
        if ! kill -0 "$SUDO_PID" 2>/dev/null; then
            SUDO_PID=""
            return 0
        fi
        sleep 1
    done
    echo "agent did not stop"
    return 1
}

# stress drives the users pressure endpoint from inside the loadgen
# container (in-topology, always exits 0), so the episode leaves no
# stray host-process lifecycle noise in the Lens windows.
stress() {
    docker compose -f demo/docker-compose.yml exec -T loadgen python -c "
import urllib.request
try:
    urllib.request.urlopen('http://gateway:8080/users/stress?mb=$1&sec=$2', timeout=$3).read()
except Exception as exc:
    print('stress request ended:', exc)
"
}

echo "== building agent (bpf + web + go) =="
make build

echo "== pre-agent workload: connections that must be seeded, not observed =="
docker compose -f demo/docker-compose.yml up -d --quiet-pull cache holdconn
for i in $(seq 1 60); do
    if docker logs atlas-demo-holdconn 2>&1 | grep -q "connected"; then
        break
    fi
    sleep 1
done
docker logs atlas-demo-holdconn 2>&1 | tail -1
CACHE_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' atlas-demo-cache)
# A host process holding an idle connection into the container: seeding
# must attribute both the host and the container side.
python3 - "$CACHE_IP" <<'PYEOF' &
import socket, sys, time
s = socket.create_connection((sys.argv[1], 6379), timeout=5)
s.sendall(b"PING\r\n")
print("host holdconn:", s.recv(64), flush=True)
while True:
    time.sleep(3600)
PYEOF
HOST_HOLD_PID=$!
sleep 2

echo "== starting atlas agent with real eBPF (sudo) =="
start_agent
echo "agent is up"

echo "== phase 0: startup seeding discovered the pre-existing connections =="
sleep 5
node scripts/assert-seed.mjs "$BASE_URL" discover

echo "== starting the rest of the demo workload =="
docker compose -f demo/docker-compose.yml up -d --quiet-pull

echo "== era A: letting traffic flow (45s) =="
sleep 45
T1=$(date +%s)

echo "== phase 1: live topology, health, unix IPC, resources, app view =="
node scripts/assert-graph.mjs "$BASE_URL"

echo "== lifecycle episode: restarting inventory =="
docker compose -f demo/docker-compose.yml restart -t 2 inventory

echo "== pressure episode: sustained RSS climb, then an OOM kill =="
# Hold ~200M inside the 256M limit long enough for the 10s sampler.
stress 200 14 30
sleep 2
T_OOM=$(date +%s)
# Then exceed the limit: the kernel OOM-kills the container and docker
# restarts it (restart: on-failure).
stress 300 5 25

echo "== letting the restarts settle and the sampler flush (30s) =="
sleep 30

echo "== phase 1b: lifecycle + resource evidence =="
node scripts/assert-v3.mjs "$BASE_URL" "$T1"

echo "== phase 1c: Incident Lens over the OOM episode =="
node scripts/assert-lens.mjs "$BASE_URL" oom "$T_OOM" "$(date +%s)"

echo "== quiet separation before the next incident (25s) =="
sleep 25

echo "== dependency change: stopping inventory =="
T_STOP=$(date +%s)
docker compose -f demo/docker-compose.yml stop -t 2 inventory

echo "== era B: letting the change age past the presence window (130s) =="
sleep 130
T2=$(date +%s)

echo "== phase 2: replay + compare across the change =="
node scripts/assert-lifecycle.mjs "$BASE_URL" "$T1" "$T2" "PHASE 2"

echo "== phase 2b: Incident Lens over the stop incident =="
LENS_FROM=$((T_STOP - 45))
node scripts/assert-lens.mjs "$BASE_URL" stop "$LENS_FROM" "$T2"

echo "== restarting the agent (history must survive) =="
stop_agent
start_agent
echo "agent restarted"

echo "== phase 3: history intact after restart =="
node scripts/assert-lifecycle.mjs "$BASE_URL" "$T1" "$T2" "PHASE 3 (post-restart)"

echo "== phase 3b: the restarted agent re-seeds still-standing connections =="
sleep 5
node scripts/assert-seed.mjs "$BASE_URL" discover

echo "== phase 3c: the Lens reads the same recorded incident after restart =="
node scripts/assert-lens.mjs "$BASE_URL" stop "$LENS_FROM" "$T2"

echo "== letting the restarted agent observe live traffic (25s) =="
sleep 25
LIVE_EDGES=$(curl -fsS "$BASE_URL/api/appview" | node -e "let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{const j=JSON.parse(d);console.log(j.edges.filter(e=>e.src==='svc:compose:atlas-demo/gateway').length)})")
if [ "$LIVE_EDGES" -lt 1 ]; then
    echo "restarted agent sees no live gateway traffic"
    exit 1
fi
echo "restarted agent is observing live traffic (gateway edges: $LIVE_EDGES)"

echo "== phase 3d: the restarted agent RECORDS new history (not just reads old) =="
T3=$(date +%s)
POST_RESTART=$(curl -fsS "$BASE_URL/api/appview?at=$T3&presence=30" | node -e "let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{const j=JSON.parse(d);const e=j.edges.find(e=>e.src==='svc:compose:atlas-demo/gateway');console.log(e&&e.window&&e.window.opens>=1?'ok':'missing')})")
if [ "$POST_RESTART" != "ok" ]; then
    echo "post-restart era not present in history (replay at T3 shows no gateway activity)"
    curl -fsS "$BASE_URL/api/appview?at=$T3&presence=30" || true
    exit 1
fi
echo "post-restart era reconstructs from newly recorded history"

echo "== atlas top: terminal client smoke test =="
TOP_OUT=$(./bin/atlas top --once --url "$BASE_URL")
echo "$TOP_OUT" | head -12
for want in "ATLAS TOP" "SERVICE" "CPU%" "gateway" "orders"; do
    if ! echo "$TOP_OUT" | grep -q "$want"; then
        echo "atlas top output missing: $want"
        exit 1
    fi
done
echo "atlas top OK"

if [ "${ATLAS_E2E_UI:-1}" != "0" ]; then
    echo "== UI end-to-end (headless chromium) =="
    node web/scripts/ui-smoke.mjs "$BASE_URL" "$T1" "$T2" "$LENS_FROM"
fi

echo "== phase 4: seeded connections reconcile when they finally close =="
docker compose -f demo/docker-compose.yml stop -t 2 holdconn
kill "$HOST_HOLD_PID" 2>/dev/null || true
HOST_HOLD_PID=""
node scripts/assert-seed.mjs "$BASE_URL" reconcile

echo "== e2e complete =="

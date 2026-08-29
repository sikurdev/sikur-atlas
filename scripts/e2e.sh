#!/usr/bin/env bash
# End-to-end check: build everything, run the agent with real eBPF, run
# the demo workload, stop one service mid-run, and assert that live
# discovery, health signals, Replay, Compare and restart survival all
# work against the real kernel. Requires Linux, docker and sudo.
set -euo pipefail
cd "$(dirname "$0")/.."

BASE_URL="http://127.0.0.1:7171"
AGENT_LOG="$(mktemp /tmp/atlas-e2e-XXXX.log)"
DB_DIR="$(mktemp -d /tmp/atlas-e2e-db-XXXX)"
SUDO_PID=""

cleanup() {
    status=$?
    set +e
    echo "== agent log =="
    cat "$AGENT_LOG" || true
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

echo "== building agent (bpf + web + go) =="
make build

echo "== starting atlas agent with real eBPF (sudo) =="
start_agent
echo "agent is up"

echo "== starting demo workload =="
docker compose -f demo/docker-compose.yml up -d --quiet-pull

echo "== era A: letting traffic flow (45s) =="
sleep 45
T1=$(date +%s)

echo "== phase 1: live topology, health, application view =="
node scripts/assert-graph.mjs "$BASE_URL"

echo "== lifecycle change: stopping inventory =="
docker compose -f demo/docker-compose.yml stop -t 2 inventory

echo "== era B: letting the change age past the presence window (130s) =="
sleep 130
T2=$(date +%s)

echo "== phase 2: replay + compare across the change =="
node scripts/assert-lifecycle.mjs "$BASE_URL" "$T1" "$T2" "PHASE 2"

echo "== restarting the agent (history must survive) =="
stop_agent
start_agent
echo "agent restarted"

echo "== phase 3: history intact after restart =="
node scripts/assert-lifecycle.mjs "$BASE_URL" "$T1" "$T2" "PHASE 3 (post-restart)"

echo "== letting the restarted agent observe live traffic (25s) =="
sleep 25
LIVE_EDGES=$(curl -fsS "$BASE_URL/api/appview" | node -e "let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{const j=JSON.parse(d);console.log(j.edges.filter(e=>e.src==='svc:compose:atlas-demo/gateway').length)})")
if [ "$LIVE_EDGES" -lt 1 ]; then
    echo "restarted agent sees no live gateway traffic"
    exit 1
fi
echo "restarted agent is observing live traffic (gateway edges: $LIVE_EDGES)"

echo "== phase 3b: the restarted agent RECORDS new history (not just reads old) =="
T3=$(date +%s)
POST_RESTART=$(curl -fsS "$BASE_URL/api/appview?at=$T3&presence=30" | node -e "let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{const j=JSON.parse(d);const e=j.edges.find(e=>e.src==='svc:compose:atlas-demo/gateway');console.log(e&&e.window&&e.window.opens>=1?'ok':'missing')})")
if [ "$POST_RESTART" != "ok" ]; then
    echo "post-restart era not present in history (replay at T3 shows no gateway activity)"
    curl -fsS "$BASE_URL/api/appview?at=$T3&presence=30" || true
    exit 1
fi
echo "post-restart era reconstructs from newly recorded history"

if [ "${ATLAS_E2E_UI:-1}" != "0" ]; then
    echo "== UI end-to-end (headless chromium) =="
    node web/scripts/ui-smoke.mjs "$BASE_URL" "$T1" "$T2"
fi

echo "== e2e complete =="

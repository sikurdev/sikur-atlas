#!/usr/bin/env bash
# End-to-end check: build everything, run the demo workload, run the
# agent with real eBPF, and assert that the discovered graph contains the
# expected multi-service topology. Requires Linux, docker and sudo.
set -euo pipefail
cd "$(dirname "$0")/.."

BASE_URL="http://127.0.0.1:7171"
AGENT_LOG="$(mktemp /tmp/atlas-e2e-XXXX.log)"
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
    exit $status
}
trap cleanup EXIT

echo "== building agent (bpf + web + go) =="
make build

echo "== starting atlas agent with real eBPF (sudo) =="
sudo ./bin/atlas --listen 127.0.0.1:7171 >"$AGENT_LOG" 2>&1 &
SUDO_PID=$!
for i in $(seq 1 20); do
    if curl -fsS "$BASE_URL/api/meta" >/dev/null 2>&1; then
        break
    fi
    if ! kill -0 "$SUDO_PID" 2>/dev/null; then
        echo "agent exited during startup"
        exit 1
    fi
    sleep 1
done
curl -fsS "$BASE_URL/api/meta" >/dev/null || { echo "agent API never came up"; exit 1; }
echo "agent is up"

echo "== starting demo workload =="
docker compose -f demo/docker-compose.yml up -d --quiet-pull

echo "== letting traffic flow (30s) =="
sleep 30

echo "== asserting discovered graph =="
node scripts/assert-graph.mjs "$BASE_URL"

if [ "${ATLAS_E2E_UI:-1}" != "0" ]; then
    echo "== UI smoke test (headless chromium) =="
    node web/scripts/ui-smoke.mjs "$BASE_URL" atlas-ui-e2e.png
fi

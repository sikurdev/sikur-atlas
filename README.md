# Sikur Atlas

Atlas draws a live map of which processes and containers on a Linux
machine talk to each other, from real kernel events. Run one binary as
root, open one page, watch the topology appear as traffic happens. No
instrumentation, no sidecars, no config.

It works by tracing TCP connection lifecycles with eBPF (a stable
tracepoint plus one kretprobe), attributing each connection end to a
process or Docker container, and merging the two halves of every
connection into a directed service graph served over HTTP with live
updates.

![Atlas UI showing the demo topology](docs/atlas-ui.png)

## Quick start

Requirements: Linux kernel ≥ 5.8 with BTF (`/sys/kernel/btf/vmlinux`
exists — true for all mainstream distro kernels), root or
`CAP_BPF`+`CAP_PERFMON`, Go ≥ 1.25, Node ≥ 20, clang.

```bash
make build          # compiles the eBPF object, the web UI and the agent
sudo ./bin/atlas    # serves http://localhost:7171
```

Every TCP connection opened from now on shows up within about a second.
`curl example.com` gives you your first edge.

### The demo topology

`demo/` contains a six-service workload (nginx gateway, two Python APIs,
an inventory service, Redis, a load generator) that Atlas discovers from
its actual traffic:

```bash
make demo-up        # docker compose; unmodified public images, no builds
```

Within ~30 seconds the graph shows
`loadgen → gateway → {orders, users}`, `orders → {inventory, cache}` and
`users → cache`, with connection counts and byte totals on every edge.
`make demo-down` removes it. `make e2e` runs the same thing
non-interactively and asserts the discovered graph (CI runs this on every
push, including a headless-browser check of the UI).

## What you see

- **Nodes** are containers (grouped by container, named via the Docker
  socket when readable), host processes (grouped by executable), or
  external endpoints. Each exposes pids, executable, listening ports,
  observed addresses, first/last seen.
- **Edges** are observed TCP connections toward a server port:
  connection count, currently-active count, bytes in both directions,
  first/last seen. Byte counters come from the kernel's per-socket
  lifetime counters and are folded in when a connection closes.

What Atlas deliberately does not do in v0.1: UDP, packet payloads,
Kubernetes, multi-host, HTTP-level parsing, authentication, history
beyond the agent's uptime. Connections already established before the
agent starts are only seen when they close. See
[docs/architecture.md](docs/architecture.md) for how it works and where
the seams for those features are.

## Privileges

The agent loads two read-only BPF programs (a tracepoint on
`sock:inet_sock_set_state` and a kretprobe on `inet_csk_accept`) and
reads `/proc` for process metadata. That needs root, or
`CAP_BPF`+`CAP_PERFMON` on recent kernels. It never reads packet
payloads; events carry addresses, ports, pids, comm names and byte
counts only. The API listens on `127.0.0.1` by default.

## Development

```bash
make verify   # deterministic gate: bpf build, vet, golangci-lint,
              # go test, tsc, eslint, vitest, UI build, agent build
make e2e      # full end-to-end: agent + demo + graph assertions (Linux)
make bpf      # just the eBPF object (clang; BPF_CC="zig cc" works too)
```

The Go tests run on any OS, including validation of the compiled BPF
object's BTF against the Go event decoder. Everything kernel-dependent is
verified in CI on a real kernel by `make e2e`.

Layout: `bpf/` C programs, `internal/ebpf` loading and decoding,
`internal/collector` connection correlation, `internal/graph` the store,
`internal/api` HTTP/SSE, `web/` the React UI, `demo/` the workload,
`scripts/` e2e harness.

## License

Apache-2.0. Vendored BPF helper headers in `bpf/include/` are
BSD-2-Clause (from libbpf via cilium/ebpf); IBM Plex fonts in
`web/public/fonts/` are OFL-1.1.

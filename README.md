# Sikur Atlas

Atlas draws a live map of which services on a Linux machine talk to each
other, from real kernel events — and remembers it. Scrub backwards
through time, compare two moments, and ask the **Incident Lens** what
broke first: a deterministic investigation over the recorded evidence
that reconstructs the chain — the OOM kill, the service that vanished,
the dependencies that started failing — names the likely origin only
when the timestamps and the dependency graph actually support it, and
shows blast radius and recovery. No instrumentation, no sidecars, no
Prometheus, no config — and no guessing: every conclusion links to the
recorded facts behind it.

It traces TCP connection lifecycles and AF_UNIX socket traffic with
eBPF, seeds the map at startup from the kernel's own socket tables (so
connections that predate the agent are standing on the map within
seconds, not invisible), attributes each connection end to a process or
Docker container, groups containers into their Compose services,
records process lifecycle (exec, exit, crash, OOM kill) and per-service
resource usage (CPU, memory, disk I/O, throttling, pressure), and
stores everything in a local SQLite file so the topology has a past,
not just a present. A terminal client, `atlas top`, shows the same
picture over SSH.

![Atlas live view: the demo topology mid-incident, with a failing
dependency in red](docs/atlas-ui.png)

## Quick start

Requirements: Linux kernel ≥ 5.8 with BTF (`/sys/kernel/btf/vmlinux`
exists — true for all mainstream distro kernels), root or
`CAP_BPF`+`CAP_PERFMON`, Go ≥ 1.25, Node ≥ 20, clang.

```bash
make build          # compiles the eBPF object, the web UI and the agent
sudo ./bin/atlas    # serves http://localhost:7171
```

Connections that already exist when Atlas starts are seeded from the
kernel's socket tables within a few seconds — a long-lived database
connection is on the map immediately, marked as discovered-standing
rather than observed opening. Every TCP connection opened from now on
shows up within about a second; `curl example.com` gives you your first
live edge. History lands in `/var/lib/sikur-atlas/history.db` (`--db`
to move it).

No browser at hand? The same binary is the terminal client:

```bash
atlas top             # live table: services, cpu, memory, traffic, failures
atlas top --once      # one frame, suitable for scripts and CI
```

`atlas top` talks to the agent's HTTP API (`--url` to point it at a
non-default address), so it needs no privileges of its own and shows
exactly what the web UI shows: the service-level view with resource and
health columns, sortable, filterable, with per-service drill-down.

### The demo topology

`demo/` contains an eight-service workload (nginx gateway, three Python
APIs, an inventory service, Redis, a load generator, and a client that
holds one idle connection open forever — the seeding demo) that Atlas
discovers from its actual traffic and standing kernel state:

```bash
make demo-up        # docker compose; unmodified public images, no builds
```

Within ~30 seconds the Services view shows
`loadgen → gateway → {orders, users}`, `orders → {inventory, cache}`,
`users → cache` — and one edge that is not TCP at all: `orders →
reports` over an AF_UNIX socket (`/sockets/reports.sock` in a shared
volume), drawn from the kernel's own socket table and connect events.
Every service also carries live resources: CPU, memory against its
limit, disk I/O, process/thread/fd counts. One deliberate defect is
included: `users` tries `cache:6380` on every request, where nothing
listens — so you can see what a failing dependency looks like (red
edge, failure and reset counts) from real refused connections.

Now break things and watch Atlas remember:

```bash
docker compose -f demo/docker-compose.yml stop inventory
# wait a couple of minutes, then in the UI:
#   - scrub the timeline back: inventory is there in the past
#   - "Pin A" on a past moment, pick a present moment: Compare lists
#     "− inventory" and "− orders → inventory:8000"

curl "localhost:8080/users/stress?mb=300&sec=5"
# users allocates past its 256 MiB limit: the kernel OOM-kills it,
# docker restarts it. The timeline gets an OOM marker, the inspector
# shows the kill and the restart exec, and Compare between a moment
# before and after lists the lifecycle events with the RSS climb.
```

![Compare: inventory removed between the two moments, with the cascade
it caused](docs/atlas-compare.png)

```bash
# Ask the Lens what happened: pick the window around the breakage.
curl "localhost:7171/api/lens?from=$(date -d '-10 min' +%s)&to=$(date +%s)"
# → origin: inventory (exit, killed by signal 15), blast radius:
#   orders + the stopped orders → inventory edge, chronic context:
#   users → cache:6380 (broken since before the window) — or the ⌖ Lens
#   button in the UI for the same report with jump-to-Replay per finding.
```

![Incident Lens: a SIGKILLed service named as the likely origin, with
the inference badge, the rule that produced it, and the recorded
evidence expanded — captured live on a minimal kernel running in
degraded mode, seeded holdconn → cache edge on the
map](docs/atlas-lens.png)

`make demo-down` removes the workload. `make e2e` runs this whole story
non-interactively — connections established *before* the agent starts
(container and host) that must appear seeded without replacement
traffic, a real restart, a real OOM kill, a real service stop, Lens
investigations of both incidents asserted against the recorded
evidence, an agent restart to prove history survives and re-seeds, seed
reconciliation when the held connections finally close, an `atlas top`
smoke test, and a headless-browser pass over live view, IPC edges,
resources, lifecycle, Replay, Compare, Focus, filtering, the seeded
inspector and the Lens panel (CI does this on every push).

## What you see

- **Services view** (default): containers grouped by Docker Compose
  service, host processes grouped by executable, well-known
  infrastructure (dockerd, systemd, sshd, …) and Atlas itself hidden
  behind a "system" toggle, external endpoints collapsed into one node.
  **Raw view**: every process, container and endpoint, ungrouped.
- **Overview layout**: a directed left-to-right dependency layout.
  **Explore**: free-form force layout you can drag.
- **Edges** carry health from kernel evidence: connection rate, active
  connections, failed connects, RSTs received, retransmitted segments,
  smoothed RTT (handshake and close samples), bytes on close. AF_UNIX
  edges render beside TCP ones, labeled with their socket path, with
  connect and failure counts of their own. Connections that predate the
  agent count as active with explicit `seeded` provenance — never as
  observed opens.
- **Resources** on every service: CPU (with cgroup throttling), RSS
  against the memory limit, disk I/O, process/thread/fd counts, and PSI
  pressure where the kernel provides it — sampled, recorded, and shown
  in the inspector next to the topology they belong to.
- **Lifecycle**: process exec, exit, crash (fatal signal) and OOM-kill
  events, attributed to their service, drawn as timeline markers and
  listed in the inspector — so a restart or kill is visible history,
  not a gap you have to infer.
- **Timeline + Replay**: the strip at the bottom shows recorded
  activity and lifecycle markers; click to view the topology as it
  stood at that moment. **Compare** pins moment A against moment B and
  lists added/removed services and edges, meaningful health changes,
  resource movements (CPU, RSS, throttling, OOM kills), and the
  lifecycle events between the two moments — computed from recorded
  evidence with fixed thresholds, never guessed.
- **Incident Lens**: select a window (or a service) and get a
  deterministic investigation from the recorded evidence — the
  chronological chain of findings (each with timestamps and the raw
  recorded numbers), the likely origin *only* when temporal and
  dependency evidence supports it (otherwise an explicit "unresolved"
  with the reason), the observed blast radius, and recovery. Findings
  are facts; the origin and propagation links are the only inferences
  and are labeled as such. Every finding jumps Replay to its moment;
  the origin can be focused on the map. The rules are documented
  constants (`lens/v1` in
  [docs/architecture.md](docs/architecture.md)) — no model, no scores.
- **Focus** dims everything outside a service's transitive callers and
  dependencies (its blast radius).
- **`atlas top`**: the same service table in a terminal — sort (`s`),
  filter (`/`), focus (`f`), per-service drill-down (Enter) — rendered
  from the same API, so SSH into a box is enough.

Retention: 10-second buckets for 2 hours, 5-minute buckets for 7 days,
in one local SQLite file — resource samples compact on the same
schedule, lifecycle events keep full resolution for the 7 days. See
[docs/architecture.md](docs/architecture.md) for the exact semantics of
every metric, the reconstruction windows, the complete Incident Lens
rule set, the startup-seeding semantics, and the known limitations
(metrics only measurable at close, no health attribution for seeded
connections until they close, AF_UNIX path ambiguity across mount
namespaces, and friends).

## Privileges and privacy

The agent loads read-only BPF programs on stable tracepoints
(`sock:inet_sock_set_state`, `tcp:tcp_retransmit_skb`,
`tcp:tcp_receive_reset`, `sched:sched_process_exec`,
`sched:sched_process_exit`, `oom:mark_victim`) and probes on
`inet_csk_accept` and `unix_stream_connect` (kprobes — present on all
mainstream distro kernels; on a kernel built without `CONFIG_KPROBES`
Atlas starts degraded, says so in the log, `/api/meta` and the UI
footer, and loses server-side accept attribution and AF_UNIX connect
counting while everything tracepoint- and scan-based keeps working); it
dumps the AF_UNIX socket table over netlink
`sock_diag` in each network namespace (via `setns`), reads the
per-namespace TCP socket tables once at startup to seed pre-existing
connections (and every 30 s to re-verify them), and reads `/proc` and
cgroup v2 files for process metadata and resource samples. Run it as root: the BPF side alone can work with
`CAP_BPF`+`CAP_PERFMON`, but namespace entry needs `CAP_SYS_ADMIN` and
the resource sampler reads other processes' `/proc` files.

It never reads packet or socket payloads; events carry addresses,
ports, socket paths, pids, comm names, executable paths, exit codes,
byte counts, RTT estimates and resource counters only. Overhead is
bounded by design: fixed-size kernel maps, a 1 MiB ring buffer that
drops (and counts) rather than blocks, resource sampling only for
processes already in the topology, and lifecycle recording capped per
node per flush. The API listens on `127.0.0.1` by default and has no
authentication — do not expose it beyond localhost.

## Development

```bash
make verify   # deterministic gate: bpf build, vet, golangci-lint,
              # go test, tsc, eslint, vitest, UI build, agent build
make e2e      # full end-to-end incl. replay/compare/restart (Linux)
make bpf      # just the eBPF object (clang; BPF_CC="zig cc" works too)
```

The Go tests run on any OS — including the history store (pure-Go
SQLite) and a validation of the compiled BPF object's BTF against the Go
event decoder. Everything kernel-dependent is verified in CI on a real
kernel by `make e2e`.

Layout: `bpf/` C programs, `internal/ebpf` loading and decoding,
`internal/collector` connection/lifecycle correlation and startup
seeding, `internal/unixdiag` the AF_UNIX socket-table dump,
`internal/resources` the cgroup/procfs sampler, `internal/graph` the
live store, `internal/history` the SQLite history behind
Replay/Compare/Lens, `internal/appview` the service-level projection
and diff, `internal/lens` the Incident Lens rule engine, `internal/api`
HTTP/SSE, `internal/tui` the `atlas top` client, `web/` the React UI,
`demo/` the workload, `scripts/` the e2e harness.

## License

Apache-2.0. Vendored BPF helper headers in `bpf/include/` are
BSD-2-Clause (from libbpf via cilium/ebpf); IBM Plex fonts in
`web/public/fonts/` are OFL-1.1.

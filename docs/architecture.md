# Architecture

One process, four stages: kernel events → correlation → graph → API/UI.

```
 kernel                agent (Go)                              browser
┌───────────────┐     ┌─────────────┐  ┌───────────┐  ┌─────┐  ┌────┐
│ tracepoint    │ ring│ decode      │  │ correlator│  │graph│  │ UI │
│ sock/inet_    │─buf─▶ (internal/  │─▶│ (internal/│─▶│store│─▶│SSE │
│ sock_set_state│     │  ebpf)      │  │ collector)│  │     │  │    │
│ kretprobe     │     └─────────────┘  └─────┬─────┘  └─────┘  └────┘
│ inet_csk_     │                            │ pid → identity
│ accept        │                      ┌─────▼─────┐ ┌───────────┐
└───────────────┘                      │ /proc     │ │ docker.sock│
                                       │ (procfs)  │ │ (optional) │
                                       └───────────┘ └───────────┘
```

## Kernel side (bpf/atlas.bpf.c)

Two attach points cover the whole TCP connection lifecycle:

**`tracepoint:sock/inet_sock_set_state`** — a stable-ABI tracepoint that
fires on every TCP state transition, kernel-wide, across all network
namespaces (which is what makes containers visible with no per-container
setup). Three transitions matter:

- `→ SYN_SENT`: an outbound `connect()` running in the owning process's
  context. This is the only client-side moment where
  `bpf_get_current_pid_tgid()` is trustworthy, so pid/comm are captured
  here. The source port may not be assigned yet (the kernel binds it
  after setting the state), so the tuple is not trusted until
  establishment.
- `→ ESTABLISHED`: handshake done. Fires in softirq context, so no pid —
  but it carries the full 4-tuple and the socket identity.
- `→ CLOSE`: the socket's lifetime data-octet counters
  (`tcp_sock.bytes_sent`/`bytes_received`, RFC 4898, kernel ≥ 4.19) are
  read here via CO-RE and shipped with the event. Unlike `bytes_acked`
  they never count SYN/FIN sequence space; `bytes_sent` does include
  retransmitted octets.

**`kretprobe:inet_csk_accept`** — `accept()` returning in the server
process. The only place server-side pid/comm attribution is truthful.
The new socket's tuple is read from `sock_common` via CO-RE.

Events (96-byte fixed struct, little-endian) stream over a 512 KiB ring
buffer; a per-CPU counter records drops, exposed at `/api/meta`. The
programs never read packet payloads — only connection metadata.

CO-RE without the 3 MB generated header: `bpf/include/vmlinux_min.h`
declares just the dozen kernel types the programs touch, all marked
`preserve_access_index`, so libbpf relocates field offsets against the
running kernel's BTF at load time. Only field names must match, which a
real kernel verifies on every CI run.

The compiled object is embedded in the Go binary (`go:embed`) and its
BTF is cross-checked against the Go decoder's offsets by a unit test
that runs on any OS (`internal/ebpf/event_test.go`) — the C and Go sides
of the wire format cannot drift silently.

## Correlation (internal/collector)

A TCP connection between two local endpoints is observed as *two*
kernel sockets: the client's and the server's, with mirrored 4-tuples.
The correlator keys per-socket state by kernel socket address and merges
both halves into one logical connection record keyed by the canonical
(order-independent) tuple:

- client half: OPEN (pid) → ESTABLISHED (tuple) → CLOSE (bytes)
- server half: ESTABLISHED (tuple) → ACCEPT (pid) → CLOSE (bytes)

A record materializes into a graph edge when it is established and
either both halves have identified themselves or a grace period (1 s)
expires — at which point the unidentified side becomes an *external*
node. Ordering quirks the state machine handles explicitly, each pinned
by a unit test:

- accept can trail the client's close under load; the close is stashed
  until the server identifies itself, so short-lived local connections
  don't get misattributed as external;
- a socket that establishes with no prior open is a server socket whose
  `accept()` hasn't returned; if it never does, an orientation hint
  keeps client and server straight;
- both halves report the same byte counters, so bytes fold into the edge
  exactly once, from whichever half closes first (mirrored when it's the
  server's);
- failed connects (SYN, no establishment) never touch the graph.

Node identity: container id from `/proc/<pid>/cgroup` when present
(node per container), else the executable path (node per binary, so
nginx workers collapse into one node), else comm. Container names and
images resolve asynchronously through the Docker socket when readable;
otherwise short ids are shown. Listening ports come from accepted
connections plus a periodic `/proc/net/tcp{,6}` scan across network
namespaces with inode→pid attribution.

## Graph and API

`internal/graph` is a mutex-guarded in-memory store — nodes, edges with
`connections / activeConns / bytes / first-last seen`, a version counter
and change subscription. Snapshots are deterministic (sorted) for
testability. v0.1 keeps no history and no persistence; retention beyond
agent uptime is a seam, not a feature.

`internal/api` serves `GET /api/graph` (snapshot), `GET /api/stream`
(SSE, full debounced snapshots — at this scale deltas would be
complexity without payoff), `GET /api/meta` (agent/collector/drop
stats), and the embedded UI.

## UI (web/)

React + TypeScript + d3-force, rendered as SVG with hand-rolled
pan/zoom/drag. Snapshots merge into the running simulation by node id,
so layout stays stable while the graph updates live. Container / process
/ external nodes use distinct map symbols (the inspector shows the key).
No UI state survives reloads on purpose — the backend is the source of
truth.

## Trust boundaries and failure modes

- Ring buffer overflow drops events rather than blocking the kernel;
  drops are counted and surfaced in the UI footer.
- Pid attribution can miss a process that exits before `/proc` is read;
  the kernel-provided comm is kept as fallback identity.
- Connections established before the agent started are invisible until
  they close (no state transition to observe). A `/proc/net` seed scan
  at startup is the obvious v0.2 fix and slots into the collector
  without schema changes.
- Tracking state is capped by a 1-hour idle TTL. An established
  connection produces no events while it lives, so a connection
  outliving the TTL ages out: its edge's active count is released, and
  bytes from its eventual close are not attributed. The same path
  reclaims state after a lost close event, and socket-address reuse
  after a lost close re-keys instead of misattributing.

## Seams for later

Each future direction has a place to land without rework: UDP means one
more program and event type through the same pipeline; persistence means
a second `graph.Store` implementation; multi-host means agents shipping
records to a merger that already thinks in canonical tuples; Kubernetes
enrichment is a sibling of `dockermeta`. None of that is scaffolded —
they're just not blocked.

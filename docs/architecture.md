# Architecture

One process, five stages: kernel events → correlation → live graph +
history → projection → API/UI.

```
 kernel                agent (Go)                                   browser
┌───────────────┐     ┌─────────┐  ┌───────────┐  ┌───────┐ ┌─────┐ ┌────┐
│ tracepoints:  │ ring│ decode  │  │ correlator│  │ graph │ │ app │ │ UI │
│ inet_sock_    │─buf─▶(internal│─▶│ (internal/│─▶│ store │▶│ view│▶│SSE │
│  set_state    │     │ /ebpf)  │  │ collector)│  │ (live)│ │(proj│ │    │
│ tcp_retransmit│     └─────────┘  └───┬───┬───┘  └───────┘ │ ect)│ └────┘
│ tcp_receive_  │                      │   │      ┌───────┐ └──▲──┘
│  reset        │        pid → identity│   └─────▶│history│────┘
│ kretprobe     │                ┌─────▼─────┐    │(sqlite│  replay /
│ inet_csk_     │                │ /proc     │    │ file) │  compare /
│  accept       │                │ (procfs)  │    └───────┘  timeline
└───────────────┘                └───────────┘ + docker.sock (optional)
```

## Kernel side (bpf/atlas.bpf.c)

Four attach points cover the TCP connection lifecycle and its health:

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

**`tracepoint:tcp/tcp_retransmit_skb`** — one event per retransmitted
segment, attributed to its connection by socket identity. This works for
long-lived connections too, unlike close-time counters.

**`tracepoint:tcp/tcp_receive_reset`** — one event per RST *received* by
a local socket. RSTs Atlas's host *sends* to remote peers are not
counted: the `tcp_send_reset` tracepoint's record grew a `reason` field
in kernel 6.10, which shifts its layout between versions, and a metric
that silently misreads on half the fleet is worse than a narrower
honest one. For local-to-local traffic both ends are local, so the
receive side captures the event anyway.

### Health signal semantics

| Signal | Source | Caveats |
| --- | --- | --- |
| RTT | `tcp_sock.srtt_us >> 3` at ESTABLISHED (handshake RTT) and CLOSE (mature estimate) | smoothed (EWMA), µs; no mid-life samples for long-lived connections |
| retransmits | `tcp:tcp_retransmit_skb`, live | per segment, includes SYN retransmits (stashed until the connection identifies itself) |
| resets | `tcp:tcp_receive_reset`, live | RSTs *received* locally only, see above |
| failed connects | socket closed out of SYN_SENT without establishing | includes refused (RST) and timed-out connects; counted on the edge towards the target, which is a container when the address identifies one, else external |
| connection rate | establishment events per bucket | — |
| active connections | opens − closes, tracked per edge | released by the idle sweep if a close event is lost |
| bytes | `tcp_sock.bytes_sent/received` (RFC 4898 data octets) at CLOSE | nothing until a connection closes; `bytes_sent` includes retransmitted octets |

Deliberately *not* shown, because they cannot be measured truthfully
from these attach points: per-request latency (needs L7 parsing),
mid-life throughput of open connections (no per-ACK sampling in v0.2),
UDP anything.

Events (104-byte fixed struct, little-endian) stream over a 1 MiB ring
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
- failed connects (SYN, no establishment) become failure counts on the
  edge towards their target — never connections. SYN retransmits and
  RSTs observed while connecting are stashed on the socket and folded
  into whichever edge the attempt resolves to.

Node identity: container id from `/proc/<pid>/cgroup` when present
(node per container), else the executable path (node per binary, so
nginx workers collapse into one node), else comm. Container names and
images resolve asynchronously through the Docker socket when readable;
otherwise short ids are shown. Listening ports come from accepted
connections plus a periodic `/proc/net/tcp{,6}` scan across network
namespaces with inode→pid attribution.

## Live graph, history, and Replay

`internal/graph` is a mutex-guarded in-memory store — the live truth:
nodes, edges with connection/health counters, a version counter and
change subscription. Snapshots are deterministic (sorted).

`internal/history` gives the topology a past. The correlator reports
edge lifecycle and health increments through a `Recorder` interface;
the history store accumulates them into **10-second buckets** and
flushes completed buckets, node metadata, and node-presence rows into a
single SQLite file (`modernc.org/sqlite`, pure Go, WAL). Listen ports
are snapshotted *per presence row*, so a replayed era shows the ports of
that era, not today's.

- **Reconstruction** (`SnapshotAt(T)`): everything with bucket activity
  or presence in a trailing *presence window* (default 120 s — safely
  above the 30 s listen-scan interval) is "present at T"; metrics are
  summed over a *metric window* (default 60 s); active connections come
  from the last bucket's end-count. Both windows are per-request query
  parameters (`presence=`, `window=`).
- **Retention**: fine buckets are compacted into 5-minute buckets after
  2 hours (sums; RTT max of maxes; the active count of the last fine
  bucket) and dropped entirely after 7 days. Replay of older moments
  works at coarser resolution.
- **Restart**: the file is the state. A restarted agent continues the
  same history; only the live in-memory view starts empty.

`internal/appview` projects any snapshot — live or reconstructed — into
the service-level Application View: containers grouped by Docker
Compose project/service (from the standard compose labels), host
processes grouped by executable and classified app vs system (a fixed
list of well-known infrastructure; anything unknown stays visible),
external endpoints collapsed into one aggregate, Atlas recognizing its
own executable. **Compare** projects two reconstructions and diffs them
deterministically: added/removed nodes and edges, plus edges whose
health moved meaningfully: failures or resets appearing where there
were none, or any counter moving by ≥50 % *and* past an absolute floor
(5 ms RTT, 5 connections, 64 KiB bytes, 3 retransmits, 1
failure/reset). The thresholds are code, not heuristics-by-vibes: the
same inputs always produce the same diff, and reversed timestamps are
normalized so A is always the earlier moment.

`internal/api` serves `GET /api/graph[?at=]`, `GET /api/appview[?at=]`,
`GET /api/compare?a=&b=`, `GET /api/timeline?from=&to=&step=`,
`GET /api/stream` (SSE; each event carries the raw snapshot *and* its
projection so the client never needs a second round trip), `GET
/api/meta`, and the embedded UI.

## UI (web/)

React + TypeScript + d3-force, rendered as SVG with hand-rolled
pan/zoom/drag. Everything the canvas draws goes through one
`DisplayGraph` shape, produced by pure adapters from the raw view, the
application view, or a compare diff — so live, Replay and Compare render
identically.

- **Overview** is a deterministic layered layout (cycle-tolerant
  longest-path layering, barycenter ordering): callers left,
  dependencies right. **Explore** is the force layout; snapshots merge
  into the running simulation by node id and only structural changes
  reheat it.
- The **timeline** polls `/api/timeline`; clicking scrubs into
  `?at=` Replay, pinning A then picking B enters `?a=&b=` Compare (both
  URL-addressable, which is also what the browser automation drives).
- **Focus** computes the transitive caller/dependency closure
  client-side and dims everything else.
- Map symbols: circle = process, square = container, stacked squares =
  compose service (with a member-count badge), dashed diamond =
  external. Hazard red is reserved for real trouble: failures, resets,
  removals in a diff. Selection stays magenta.

The inspector answers "what changed?" only from recorded evidence: the
compare panel and the per-node 10-minute digest are both rendered
straight from `/api/compare` output. There is no inference layer.

## Known limitations

- Connections established before the agent started are invisible until
  they close; the first moments of history after an agent (re)start are
  correspondingly thin.
- Bytes and the mature RTT sample only arrive when a connection closes;
  a long-lived connection shows activity (presence, retransmits, resets)
  but not throughput until teardown.
- Node metadata other than listen ports (labels, images, pids) is
  "latest known", not versioned: a renamed container replays under its
  current name. Listen ports are era-accurate (at 5-minute granularity
  once fine buckets have been compacted).
- Event timestamps map CLOCK_MONOTONIC to wall time using an offset
  captured at agent start; a suspend/resume or a large NTP step skews
  the mapping until the agent restarts.
- Replay resolution is the bucket span: 10 s for the last 2 hours, 5 min
  beyond, nothing past 7 days (defaults).
- Reset counts cover RSTs received by local sockets only.
- Compare answers with recorded facts; it does not rank causes. The
  ordering of "what broke first" within one bucket is not knowable.

## Trust boundaries and failure modes

- Ring buffer overflow drops events rather than blocking the kernel;
  drops are counted and surfaced in the UI footer.
- Pid attribution can miss a process that exits before `/proc` is read;
  the kernel-provided comm is kept as fallback identity.
- Connections established before the agent started are invisible until
  they close (no state transition to observe). A `/proc/net` seed scan
  at startup is the obvious next step and slots into the collector
  without schema changes.
- Tracking state is capped by a 1-hour idle TTL. An established
  connection produces no events while it lives, so a connection
  outliving the TTL ages out: its edge's active count is released, and
  bytes from its eventual close are not attributed. The same path
  reclaims state after a lost close event, and socket-address reuse
  after a lost close re-keys instead of misattributing.

## Seams for later

Each future direction has a place to land without rework: UDP means one
more program and event type through the same pipeline; mid-life
throughput sampling is one more recorder call feeding the same buckets;
multi-host means agents shipping records to a merger that already
thinks in canonical tuples; Kubernetes enrichment is a sibling of
`dockermeta` feeding the same projection. None of that is scaffolded —
they're just not blocked.

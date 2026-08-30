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

Nine attach points cover TCP connection lifecycles and health, AF_UNIX
connects, and process lifecycle. The TCP four first:

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

**`kprobe`+`kretprobe:unix_stream_connect`** — an AF_UNIX `connect()`
in the calling process's context. The entry probe captures the target
`sun_path` (filesystem path, or `@name` for abstract sockets) and
stashes it keyed by thread; the return probe emits one event carrying
pid, comm, path and the syscall's return code — so successful connects
and refused/missing-socket failures are both counted, attributed to
the caller. Rate and outcome only; standing pairs come from the socket
table (below).

**`tracepoint:sched/sched_process_exec`** and
**`sched/sched_process_exit`** — process lifecycle. Exec events carry
the new executable's filename; exit events fire only for the group
leader (thread exits are not service lifecycle) and carry the raw exit
code, from which the collector decodes clean exits, signal kills and
crashes. **`tracepoint:oom/mark_victim`** — fires the moment the
kernel OOM killer picks a victim, before the process is gone: pid is
the only field read, so the record layout question that plagues
version-dependent tracepoints does not arise.

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
| unix connects / failures | `unix_stream_connect` return code | stream sockets only; attributed by socket path, see AF_UNIX section |
| unix active pairs | sock_diag socket-table scan | standing connections only; a pair shorter than the scan interval shows in connect counts but not as active |

Deliberately *not* shown, because they cannot be measured truthfully
from these attach points: per-request latency (needs L7 parsing),
mid-life throughput of open connections (no per-ACK sampling),
byte counts for AF_UNIX traffic (the kernel keeps no per-socket
octet counters for unix sockets), UDP anything.

Events (168-byte fixed struct, little-endian) stream over a 1 MiB ring
buffer; a per-CPU counter records drops, exposed at `/api/meta`. The
programs never read packet or socket payloads — only connection and
process metadata.

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

## Startup state seeding (internal/procfs, internal/collector/seed.go)

An agent that only watches state *transitions* starts blind to every
connection that already exists. v0.4 closes that gap by seeding the live
graph from the kernel's own socket tables, once, at startup:

**What is read.** The same per-namespace `/proc/<pid>/net/tcp{,6}` walk
that finds listeners also parses ESTABLISHED rows (stable text ABI, no
new privileges): local/remote tuple and socket inode, per network
namespace, so container connections are seen exactly like host ones.
Other states (handshakes in flight, TIME_WAIT and friends) are
deliberately skipped — they are not standing connections, and their
imminent transitions arrive as live events anyway. Pre-existing AF_UNIX
pairs were already covered in v0.3 by the sock_diag scan.

**Attribution.** Socket inode → owning pid via the same `/proc` fd walk
the listen scan uses; pid → identity through the ordinary resolver
(container id, executable). A socket no process was found holding
resolves to an external node by address — stated as unattributed, never
guessed. Direction comes from kernel evidence: the half covered by a
same-namespace listener (same port, wildcard or exact address) is the
accepted side. A local↔local connection contributes two mirrored halves
that merge by canonical tuple, like live records. With no listener
evidence at all, the lower port is taken as the server — the same last
resort the live correlator uses — and counted in
`/api/meta`'s `seedDirHeuristic`.

**Truthful counters.** A seeded connection raises the edge's active
gauge and its `seededConns` marker, but never the cumulative
`Connections` count: the open was not observed, and inventing one would
fake a connection rate. `seededConns` is the uncertainty made explicit —
"of the standing connections here, this many predate the agent". In
history it lands through the same gauge-only path as AF_UNIX standing
pairs.

**Reconciliation with live events.** The seed scan runs *after* the BPF
programs attach, so every later close is observed:

- a close event whose socket the correlator never tracked is matched
  against the seeds by tuple; the seed is released exactly once (the
  twin socket's close finds it gone), the close event's lifetime byte
  counters — which the kernel keeps per socket, RFC 4898 — fold into
  the edge, mirrored when the closing socket was the server side, and
  the final RTT estimate is sampled;
- closes that arrive *while the scan is still walking /proc* are
  remembered and inoculate the seed pass, so a connection that died
  mid-scan is not resurrected (the buffer is dropped once seeding
  completes);
- a live connection establishing on a seeded tuple proves the seeded
  socket is gone (two established sockets cannot share a 4-tuple): the
  seed expires before the new record counts, so actives never double;
- every subsequent scan re-verifies surviving seeds against the socket
  table: a seed whose close event was lost (ring overflow) expires
  within one scan interval. Scans only ever *retire* seeds — new
  connections belong to the event stream. Seeds are exempt from the
  idle TTL for the same reason: they are re-verified by evidence, not
  by silence.

**What seeding cannot know**, stated rather than guessed: retransmit
and reset events carry only the kernel socket address, which a seeded
connection's tuple cannot be matched against — so pre-existing
connections carry no retransmit/reset attribution until they close.
Bytes and RTT arrive with the close, as for any connection. History
before the agent started obviously stays unrecorded; the seed makes the
*present* truthful, not the past.

## AF_UNIX topology (internal/unixdiag, internal/collector/unix.go)

Two independent evidence paths, deliberately kept apart because they
answer different questions:

**Standing pairs — who is connected right now.** The scan loop dumps
the kernel's AF_UNIX socket table over netlink `sock_diag`
(`UDIAG_SHOW_NAME|UDIAG_SHOW_PEER`) — the same evidence `ss -x` shows:
inode, peer inode, bound path, state. AF_UNIX sockets belong to the
network namespace of the process that created them and a dump only
sees its own namespace, so the dump runs once per namespace, entering
each via `setns` on `/proc/<pid>/ns/net` (one representative pid per
namespace, collected during the same `/proc` walk that maps socket
inodes to owning pids). Peer inodes are system-global, so pairing
works across namespaces — which is exactly the demo's case: a client
in one container connected through a shared-volume socket to a server
in another.

An edge is drawn only when the kernel's pairing gives a truthful
direction: an *unnamed* socket peered with a *named* one is
client→server (accepted stream sockets inherit the listener's name;
named datagram receivers are servers). `socketpair()` twins
(unnamed↔unnamed) and named↔named pairs carry no direction and are
skipped rather than guessed. New pairs raise the edge's active count,
vanished pairs release it.

**Connect events — how often, and does it fail.** The
`unix_stream_connect` probes count every connect attempt with its
return code, attributed to the target service through a path→owner
index built from the dump's listeners. This is what catches
connections too short to overlap a scan (a request-per-connection
client shows a connect rate even when no pair is ever seen standing)
and connects to sockets nobody listens on (failures). A path with no
known listener attributes to a placeholder external node — stated as
unknown rather than invented.

Both paths update the same edge (keyed src→dst plus socket path), and
the two counters stay distinct — connects are never derived from pair
sightings or vice versa, so nothing is double-counted.

## Process lifecycle (internal/collector/lifecycle.go)

Exec, exit and OOM events are correlated to graph nodes by pid: the
collector remembers which node each observed pid belongs to (bounded
map, populated by connection attribution and listener scans), with a
live `/proc` resolve as fallback while the process still exists. Exit
codes decode into three kinds: clean exit (status), signal kill, and
crash (the fatal-signal set: SEGV, ABRT, BUS, ILL, FPE). OOM
victims get their own kind — `mark_victim` fires while the process
still exists, so attribution is reliable even though the exit that
follows arrives as an ordinary SIGKILL.

Lifecycle is service history, not an audit log: events are recorded
only for processes that belong to services already in the topology
(every short-lived shell on the host would otherwise flood the store),
capped per node per flush window, with a drop counter in `/api/meta`
when the cap bites. Events land in their own SQLite table at full
resolution, feed timeline markers, the per-node inspector digest,
`/api/lifecycle`, and Compare — which lists the events that happened
between its two moments, so "users was OOM-killed and restarted at
14:02:41" is part of the diff, not something to infer from presence
gaps.

## Resource samples (internal/resources)

A sampler ticks every 10 s and reads, for each node currently in the
topology (never more — overhead is bounded by topology size, not
machine size):

- cgroup v2, resolved from `/proc/<pid>/cgroup`: `cpu.stat`
  (`usage_usec`, `throttled_usec`), `memory.current`, `memory.max`,
  `memory.events` (`oom_kill`), `io.stat` (summed across devices), and
  the cgroup's `cpu.pressure`/`memory.pressure` (PSI `some` averages)
  where the kernel provides them;
- `/proc` fallback for processes without a private cgroup:
  `stat`/`statm`/`io` summed across the node's known pids, fd and
  thread counts from `fd/` and `stat`.

Monotonic counters (CPU time, throttle time, I/O bytes, OOM kills)
are recorded as deltas per sample window; gauges (RSS, limits, fds,
procs) keep the sample's value, and bucket aggregation keeps their
maximum — a spike that lives shorter than a bucket still shows. Host
PSI (`/proc/pressure/*`) is read once per tick and exposed in
`/api/meta`, not attributed to any node.

Samples flush with the same staged pipeline as connection buckets into
a `node_metrics` table keyed (node, bucket, span): 10-second rows for
2 hours, compacted to 5-minute rows (sums of deltas, max of gauges),
dropped after 7 days. The appview attaches the metric window to each
service (summing deltas, max-ing gauges across group members), so
live view, Replay and Compare all carry resources; Compare reports
movements past fixed floors (250 ms CPU, 32 MiB RSS, 100 ms throttle —
an OOM kill always reports).

## atlas top (internal/tui)

A terminal client in the same binary, deliberately thin: it consumes
`/api/appview`, `/api/meta` and `/api/lifecycle` over HTTP exactly as
the web UI does, and contains no collection, correlation or projection
logic of its own — `BuildRows` maps the served projection onto table
rows and that is the whole data path. One row per service: CPU%, RSS,
active connections, connect rate, failures, worst outgoing RTT,
dependency/caller counts; sort cycling, substring filter, focus (the
same transitive-closure semantics as the web UI, computed over the
served edges), Enter for a per-service drill-down with its edges,
resources and recent lifecycle. Raw-mode ANSI rendering with no
external TUI dependency (`golang.org/x/term` only); `--once` prints a
single frame for scripts, which is how CI smoke-tests it.

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
`GET /api/lens?from=&to=[&service=]`,
`GET /api/stream` (SSE; each event carries the raw snapshot *and* its
projection so the client never needs a second round trip), `GET
/api/meta`, and the embedded UI.

## Incident Lens (internal/lens)

The Lens turns a recorded window into a deterministic investigation: a
chronological chain of findings, an origin named only when the evidence
supports it, the observed blast radius, and recovery. Three properties
are load-bearing:

- **Facts first.** Every finding is recorded data — a lifecycle event,
  an edge health bucket, a presence row, a resource bucket — with its
  timestamps and the raw numbers attached as evidence. Exactly two
  things in a report are inference, and both say so in the payload
  (`"inference": true`): the origin and the propagation links.
- **Deterministic.** The rules are fixed constants and functions (rule
  set `lens/v1`, named in every report); the same recorded window
  always produces the byte-identical report. No model, no scores, no
  LLM.
- **Honest about resolution.** Every finding is a time *interval*
  (its bucket span; one second for lifecycle events). Order is only
  claimed between non-overlapping intervals — what happened first
  *within* one bucket is not knowable, and the Lens says "unresolved"
  rather than pretending otherwise.

The Lens works at service level (the same appview projection the UI
shows), over one reconstruction whose presence window covers the whole
investigated range, so a service alive only mid-window still maps.

### Findings (lens/v1)

Terminal primaries — something stopped existing or was killed:

| kind | rule |
| --- | --- |
| `oom` | lifecycle event: the kernel OOM killer chose a process |
| `oom-cgroup` | `memory.events oom_kill` delta, unless the lifecycle event for the same kill (same service, same bucket) is present |
| `crash` | lifecycle event: fatal-signal death |
| `exit` | lifecycle event: an involuntary or erroring exit of an *app-category* service. A clean `exit(0)` is recorded as neutral `exit-clean` for every category (every short-lived tool would otherwise read as an incident), and any non-crash exit of a *system-category* service is recorded as neutral `exit-system` — supervised infrastructure (runc, shims, networkctl, service managers) exits with statuses and is TERM'd/KILL'd by its supervisors routinely, and when infrastructure actually breaks the kernel says so through the signals that stay primary everywhere: `crash`, `oom`, or the service disappearing |
| `service-gone` | a service that had listening presence produces no presence rows for ≥ 90 s (three missed 30 s listen scans) |
| `listen-lost` | presence continues but listening flips true → false |

Contributing pressure — may anchor an origin only when no terminal
primary exists: `rss-pressure` (RSS crosses 90 % of the memory limit)
and `throttle` (≥ 500 ms cgroup CPU throttling in one bucket).

Transitions — a dependency edge's health changed:

| kind | rule |
| --- | --- |
| `failures-start` | failed connects appear in a bucket after an in-window clean bucket (or on an edge first seen inside the window) |
| `resets-spike` / `retrans-spike` | ≥ 1 reset / ≥ 3 retransmits in a bucket after a clean one (first spike per edge) |
| `traffic-stop` | an edge active in ≥ 4 buckets falls silent (no opens or closes) for ≥ 90 s — the steadiness bar keeps CLI-style burst edges from reading as incidents |

Recovery: `failures-end` (failures gone *with* traffic flowing — silence
is not recovery), `traffic-resume`, `service-back`, and `exec` (restart
evidence). An edge already failing at the window start is **chronic**:
reported as context, excluded from transitions and origin logic — a
long-broken dependency must not hijack every later incident.

### The origin rule

`earliest-primary-with-dependency-support`: the earliest primary
finding anchors the incident **only when** every other primary strictly
follows it *and* transitively depends on it (a cascade), no transition
strictly precedes it, and every transition's target service is the
candidate or transitively depends on it over the window's recorded
edges. Any violation names the reason and reports unresolved: two
same-interval primaries on different services, an independent primary,
failures that predate every primary, or impact with no dependency path.
With no primary at all, failures alone stay unresolved ("the cause may
predate the window or be outside the host").

Two deliberate exclusions, both stated in the docs because they shape
what the Lens can say:

- **Atlas excludes itself.** The agent's own service and its API
  clients' edges toward it are the observer, not subjects.
- **The external aggregate gates nothing.** Transitions on edges toward
  `svc:external` are recorded facts, but what happens beyond the host
  can be neither explained nor refuted by local evidence — they neither
  veto nor support an origin, and dependency paths never traverse
  *through* the aggregate (its members are unrelated endpoints).

Blast radius is observed impact — services and edges carrying
non-chronic degradation findings — not reachability speculation.
Recovery pairs each degradation with the recorded evidence of its end,
or says "no recovery recorded within the window". Unlike origin
ordering, recovery pairing accepts a same-second tie: a supervisor's
restart exec routinely lands within the same recorded second as the
death it answers.

The UI's Lens panel renders the report next to the map: each finding
jumps Replay to its moment, the origin can be focused (the same
transitive-closure dimming as Focus), and every finding's evidence rows
expand in place. The investigation window and focus service live in the
URL (`?lf=&lt=[&ls=]`), so an investigation is a shareable address.

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

- Startup seeding covers *standing* state: TCP connections that were
  ESTABLISHED (and listeners) when the agent started. History before
  the agent start stays unrecorded; a seeded connection carries no
  retransmit/reset attribution (those events identify sockets by
  kernel address, which the seed cannot know) and no byte counts until
  it closes; seed direction without listener evidence falls back to the
  lower-port heuristic (counted in `/api/meta`). A connection whose
  close event is lost lingers as active for at most one scan interval
  (30 s) before re-verification expires it.
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
- AF_UNIX connect *events* attribute by socket path string, which is
  mount-namespace blind: two containers each binding the same path
  (say `/tmp/app.sock`) share one edge's connect counters. Standing
  pairs are exempt — they pair by socket inode, which is exact.
- A unix connection shorter than the scan interval (30 s) never shows
  as an active pair; its evidence is the connect counter. Byte counts
  for unix traffic don't exist at all (the kernel keeps none).
- Unix connect events observed before the first scan indexes the
  target's listener attribute to a placeholder path node, not the
  owning service; the index catches up within one scan interval.
- Lifecycle events are recorded only for services already on the map:
  the *first* exec of a brand-new container generally predates its
  node and is dropped (counted in `/api/meta`); restarts, exits and
  OOM kills of known services are all captured.
- Resource samples are 10 s apart; a spike living entirely between two
  samples is invisible. CPU/IO deltas need two samples, so a node's
  first window appears ~20 s after it does. PSI lines require kernel
  PSI support (`CONFIG_PSI=y`, default on mainstream distros).
- Compare answers with recorded facts; it does not rank causes. The
  ordering of "what broke first" within one bucket is not knowable —
  which is also why the Incident Lens treats findings as intervals and
  reports unresolved when primaries overlap.
- The Lens sees what Atlas records: an incident whose cause left no
  kernel-visible trace (a config change, a slow disk on another host, a
  bug that degrades responses without touching connections, lifecycle
  of a process that was never on the map) yields findings without a
  supported origin — reported as unresolved, not papered over. Its
  windows are bounded by retention like everything else.

## Trust boundaries and failure modes

- Ring buffer overflow drops events rather than blocking the kernel;
  drops are counted and surfaced in the UI footer.
- A kernel that cannot attach kprobes (built without `CONFIG_KPROBES` —
  some hardened or minimal VM kernels) starts Atlas degraded rather
  than not at all: the tracepoint pipeline, startup seeding and the
  socket-table scans all still work, while server-side accept
  attribution (unidentified halves show as external, the documented
  fallback) and AF_UNIX connect counting (standing pairs still come
  from sock_diag) are lost. Degradation is announced in the log,
  `/api/meta` (`degraded`) and the UI footer — never silent.
- Pid attribution can miss a process that exits before `/proc` is read;
  the kernel-provided comm is kept as fallback identity.
- Startup seeding closes the pre-existing-connection gap (see its
  section above); the races it cannot fully erase — a connection dying
  in the instants around the seed scan — are bounded to one scan
  interval by re-verification, and biased toward under-reporting
  (skipping) rather than inventing state.
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

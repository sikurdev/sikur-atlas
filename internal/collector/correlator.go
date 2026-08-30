// Package collector turns the kernel event stream into graph updates.
//
// Every TCP connection is observed as up to two kernel sockets: the
// client's (seen via connect) and, when the server is on the same host,
// the server's (seen via accept). The correlator merges the two halves by
// their address 4-tuple into one logical connection, resolves each side
// to a process/container identity, and reports edges to the graph store.
package collector

import (
	"net/netip"
	"path"
	"sync"
	"time"

	"github.com/sikurdev/sikur-atlas/internal/graph"
	"github.com/sikurdev/sikur-atlas/internal/model"
)

// ProcessResolver resolves a PID to its userspace identity. The comm from
// the kernel event is passed as a fallback for processes that exit before
// they can be inspected.
type ProcessResolver interface {
	Resolve(pid uint32, comm string) model.ProcessInfo
}

// Recorder receives per-edge lifecycle and health increments for
// persistence. All methods must be cheap and non-blocking; a nil
// Recorder disables recording.
type Recorder interface {
	EdgeOpened(edgeID string, at time.Time)
	EdgeClosed(edgeID string, bytesSent, bytesRecv uint64, rttUs uint32, at time.Time)
	// EdgeExpired releases an open connection whose close was never
	// observed (lost event or idle-TTL expiry).
	EdgeExpired(edgeID string, at time.Time)
	EdgeFailure(edgeID string, at time.Time)
	EdgeResets(edgeID string, n uint64, at time.Time)
	EdgeRetrans(edgeID string, n uint64, at time.Time)
	EdgeRTT(edgeID string, rttUs uint32, at time.Time)
	// EdgeConnects counts successful connects without touching the
	// standing-connection gauge (AF_UNIX: connects are exact events,
	// active pairs are sampled separately).
	EdgeConnects(edgeID string, n uint64, at time.Time)
	// EdgeActive adjusts only the standing-connection gauge.
	EdgeActive(edgeID string, delta int64, at time.Time)
	// NodeEvent records a lifecycle event (exec/exit/crash/oom) on a
	// node.
	NodeEvent(nodeID, kind string, pid uint32, detail string, at time.Time)
}

type direction int

const (
	dirUnknown direction = iota
	dirOutbound
	dirInbound
)

// connKey is the canonical (order-independent) form of a 4-tuple.
type connKey struct {
	a, b netip.AddrPort // a <= b
}

func canonKey(x, y netip.AddrPort) connKey {
	if lessAddrPort(x, y) {
		return connKey{a: x, b: y}
	}
	return connKey{a: y, b: x}
}

func lessAddrPort(x, y netip.AddrPort) bool {
	if c := x.Addr().Compare(y.Addr()); c != 0 {
		return c < 0
	}
	return x.Port() < y.Port()
}

type sockState struct {
	dir         direction
	pid         uint32
	comm        string
	dst         netip.AddrPort // connect() target, for failure attribution
	key         connKey
	hasKey      bool
	established bool
	// Health events observed before the socket joined a record
	// (e.g. SYN retransmits, RST while connecting).
	preRetrans uint64
	preResets  uint64
	lastTouch  time.Time
}

type connRecord struct {
	key      connKey
	oriented bool
	client   netip.AddrPort
	server   netip.AddrPort
	// hintServerLocal remembers the local end of a socket that reached
	// ESTABLISHED without a preceding open: that pattern is a server-side
	// socket still waiting for accept(). Used if no accept ever arrives.
	hintServerLocal netip.AddrPort
	hasHint         bool

	clientPID, serverPID   uint32
	clientComm, serverComm string
	clientSock, serverSock uint64
	sockRefs               int

	established   bool
	establishedAt time.Time
	deadline      time.Time
	connectRTTUs  uint32
	// Health events that arrived before the record materialized.
	preRetrans uint64
	preResets  uint64

	materialized bool
	edgeID       string
	bytesDone    bool
	closed       bool
	pending      *pendingClose
	lastTouch    time.Time
}

// pendingClose stashes a close that arrived before the connection's
// endpoints were fully identified (e.g. the client closed before the
// server's accept() returned).
type pendingClose struct {
	sockID     uint64
	dir        direction
	sent, recv uint64
	rttUs      uint32
	at         time.Time
}

// Stats are exported through /api/meta.
type Stats struct {
	Events           uint64 `json:"events"`
	OpenEvents       uint64 `json:"openEvents"`
	AcceptEvents     uint64 `json:"acceptEvents"`
	EstabEvents      uint64 `json:"establishedEvents"`
	CloseEvents      uint64 `json:"closeEvents"`
	RetransEvents    uint64 `json:"retransEvents"`
	ResetEvents      uint64 `json:"resetEvents"`
	FailedConns      uint64 `json:"failedConns"`
	UnixConnects     uint64 `json:"unixConnects"`
	UnixFailures     uint64 `json:"unixFailures"`
	ExecEvents       uint64 `json:"execEvents"`
	ExitEvents       uint64 `json:"exitEvents"`
	OOMEvents        uint64 `json:"oomEvents"`
	LifecycleDropped uint64 `json:"lifecycleDropped"`
	LiveSockets      int    `json:"liveSockets"`
	LiveRecords      int    `json:"liveRecords"`
}

// Correlator is safe for concurrent use; in practice one goroutine feeds
// HandleEvent/Tick and others read Stats.
type Correlator struct {
	mu       sync.Mutex
	store    *graph.Store
	resolver ProcessResolver
	grace    time.Duration
	idleTTL  time.Duration
	// onContainer fires for every containerized observation; the
	// receiver must deduplicate and never block. Set once at
	// construction (read without the lock by ObserveListen).
	onContainer func(containerID string)

	rec Recorder // nil = no persistence

	// addrIndex maps container addresses to node ids so failed connects
	// towards a local container can name their target. Host/loopback
	// addresses are deliberately not indexed (they don't identify one
	// process). unixPathIndex maps bound AF_UNIX paths — keyed by the
	// event-truncated form, carrying the owner and the full path — to
	// their owning node. Both guarded by addrMu: written and read across
	// the event path and the scan goroutines.
	addrMu        sync.Mutex
	addrIndex     map[netip.Addr]string
	unixPathIndex map[string]unixOwner

	// unixPairs tracks standing AF_UNIX pairs between scans; touched
	// only by SyncUnixTopology's goroutine.
	unixPairs map[pairKey]string

	// pidNodes remembers which node a pid last belonged to, so exit/oom
	// events can be attributed after the process is gone. Guarded by
	// addrMu.
	pidNodes map[uint32]string

	socks   map[uint64]*sockState
	records map[connKey]*connRecord
	stats   Stats
}

// Option configures a Correlator.
type Option func(*Correlator)

// WithGracePeriod sets how long a one-sided connection waits for its
// other half before being attributed to an external endpoint.
func WithGracePeriod(d time.Duration) Option {
	return func(c *Correlator) { c.grace = d }
}

// WithContainerHook registers a callback fired for every containerized
// observation. The receiver must deduplicate and must not block.
func WithContainerHook(fn func(containerID string)) Option {
	return func(c *Correlator) { c.onContainer = fn }
}

// WithIdleTTL sets how long stale tracking state survives lost close
// events before being swept.
func WithIdleTTL(d time.Duration) Option {
	return func(c *Correlator) { c.idleTTL = d }
}

// WithRecorder attaches a persistence recorder.
func WithRecorder(r Recorder) Option {
	return func(c *Correlator) { c.rec = r }
}

func New(store *graph.Store, resolver ProcessResolver, opts ...Option) *Correlator {
	c := &Correlator{
		store:         store,
		resolver:      resolver,
		grace:         time.Second,
		idleTTL:       time.Hour,
		addrIndex:     make(map[netip.Addr]string),
		unixPathIndex: make(map[string]unixOwner),
		unixPairs:     make(map[pairKey]string),
		pidNodes:      make(map[uint32]string),
		socks:         make(map[uint64]*sockState),
		records:       make(map[connKey]*connRecord),
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// HandleEvent consumes one decoded kernel event.
func (c *Correlator) HandleEvent(ev model.ConnEvent) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.stats.Events++
	switch ev.Type {
	case model.EventOpen:
		c.stats.OpenEvents++
		c.handleOpen(ev)
	case model.EventAccept:
		c.stats.AcceptEvents++
		c.handleAccept(ev)
	case model.EventEstablished:
		c.stats.EstabEvents++
		c.handleEstablished(ev)
	case model.EventClose:
		c.stats.CloseEvents++
		c.handleClose(ev)
	case model.EventRetrans:
		c.stats.RetransEvents++
		c.handleHealthEvent(ev, healthRetrans)
	case model.EventReset:
		c.stats.ResetEvents++
		c.handleHealthEvent(ev, healthReset)
	case model.EventUnixConnect:
		c.stats.UnixConnects++
		c.handleUnixConnect(ev)
	case model.EventExec:
		c.stats.ExecEvents++
		c.handleLifecycle(ev)
	case model.EventExit:
		c.stats.ExitEvents++
		c.handleLifecycle(ev)
	case model.EventOOM:
		c.stats.OOMEvents++
		c.handleLifecycle(ev)
	}
	c.stats.LiveSockets = len(c.socks)
	c.stats.LiveRecords = len(c.records)
}

func (c *Correlator) handleOpen(ev model.ConnEvent) {
	// connect() in process context. The source port may not be assigned
	// yet, so the tuple is not trusted until EventEstablished; the
	// destination is, and is kept for failure attribution.
	st := c.sock(ev.SockID, ev.Time)
	// A fresh connect on a known socket address means the kernel reused
	// it after a close we never saw: shed every trace of the old
	// connection so nothing leaks into (or out of) the new one.
	c.detachSock(st, ev.Time)
	st.dir = dirOutbound
	st.pid = ev.PID
	st.comm = ev.Comm
	st.dst = ev.Dst
	st.established = false
	st.preRetrans = 0
	st.preResets = 0
}

// detachSock releases a socket's link to its connection record,
// dropping the record when this was its last reference.
func (c *Correlator) detachSock(st *sockState, at time.Time) {
	if !st.hasKey {
		return
	}
	if old, ok := c.records[st.key]; ok {
		old.sockRefs--
		if old.sockRefs <= 0 {
			c.dropRecord(st.key, old, at)
		}
	}
	st.hasKey = false
}

type healthKind int

const (
	healthRetrans healthKind = iota
	healthReset
)

// handleHealthEvent attributes a retransmit/reset to the socket's edge,
// or stashes it until the connection is identified.
func (c *Correlator) handleHealthEvent(ev model.ConnEvent, kind healthKind) {
	st, ok := c.socks[ev.SockID]
	if !ok {
		return // socket predates Atlas
	}
	st.lastTouch = ev.Time
	var rec *connRecord
	if st.hasKey {
		rec = c.records[st.key]
	}
	if rec != nil {
		// A retransmitting connection is alive: keep it from being
		// idle-swept while it degrades.
		rec.lastTouch = ev.Time
	}
	if rec == nil || !rec.materialized {
		switch {
		case rec != nil && kind == healthRetrans:
			rec.preRetrans++
		case rec != nil:
			rec.preResets++
		case kind == healthRetrans:
			st.preRetrans++
		default:
			st.preResets++
		}
		return
	}
	switch kind {
	case healthRetrans:
		c.store.EdgeRetrans(rec.edgeID, 1, ev.Time)
		if c.rec != nil {
			c.rec.EdgeRetrans(rec.edgeID, 1, ev.Time)
		}
	case healthReset:
		c.store.EdgeResets(rec.edgeID, 1, ev.Time)
		if c.rec != nil {
			c.rec.EdgeResets(rec.edgeID, 1, ev.Time)
		}
	}
}

func (c *Correlator) handleAccept(ev model.ConnEvent) {
	st := c.sock(ev.SockID, ev.Time)
	// Identity is assigned after attachSock so its reuse-reset cannot
	// wipe these fresh values.
	key := canonKey(ev.Src, ev.Dst)
	rec := c.attachSock(st, key, ev.Time)
	st.dir = dirInbound
	st.pid = ev.PID
	st.comm = ev.Comm
	rec.server = ev.Src // local end of the accepted socket
	rec.client = ev.Dst
	rec.oriented = true
	rec.serverPID = ev.PID
	rec.serverComm = ev.Comm
	rec.serverSock = ev.SockID
	st.established = true
	c.markEstablished(rec, ev.Time)
	c.tryMaterialize(rec, ev.Time, false)
}

func (c *Correlator) handleEstablished(ev model.ConnEvent) {
	st := c.sock(ev.SockID, ev.Time)
	key := canonKey(ev.Src, ev.Dst)
	rec := c.attachSock(st, key, ev.Time)
	st.established = true

	if ev.SRTTMicros > 0 && rec.connectRTTUs == 0 {
		rec.connectRTTUs = ev.SRTTMicros
	}
	// Health events stashed while the socket was connecting move to the
	// record so they survive until materialization.
	rec.preRetrans += st.preRetrans
	rec.preResets += st.preResets
	st.preRetrans = 0
	st.preResets = 0

	switch st.dir {
	case dirOutbound:
		rec.client = ev.Src
		rec.server = ev.Dst
		rec.oriented = true
		rec.clientPID = st.pid
		rec.clientComm = st.comm
		rec.clientSock = ev.SockID
	case dirInbound:
		// Accept already recorded everything.
	default:
		// Established with no prior open on this socket: almost always a
		// server-side socket whose accept() has not returned yet.
		rec.hintServerLocal = ev.Src
		rec.hasHint = true
	}
	c.markEstablished(rec, ev.Time)
	c.tryMaterialize(rec, ev.Time, false)
}

func (c *Correlator) handleClose(ev model.ConnEvent) {
	st, ok := c.socks[ev.SockID]
	if !ok {
		// Socket predates Atlas (or is a listen socket): nothing tracked.
		return
	}
	delete(c.socks, ev.SockID)
	if !st.hasKey {
		// Never established. An outbound socket with a known target is a
		// failed connect — a first-class health signal.
		c.noteFailedConnect(st, ev)
		return
	}
	rec, ok := c.records[st.key]
	if !ok {
		return
	}
	rec.sockRefs--
	rec.lastTouch = ev.Time
	pc := pendingClose{
		sockID: ev.SockID, dir: st.dir,
		sent: ev.BytesSent, recv: ev.BytesRecv,
		rttUs: ev.SRTTMicros, at: ev.Time,
	}

	if !rec.established {
		// Never handshaked (reset before establishment); no edge exists.
		if rec.sockRefs <= 0 {
			delete(c.records, st.key)
		}
		return
	}

	if !rec.materialized {
		// Wait for the other half to identify itself (accept can trail
		// the client's close, and the server's establish event can be
		// lost) or for the grace deadline; Tick materializes, applies
		// the stash and cleans up. Forcing materialization here would
		// commit to endpoints that better evidence may contradict
		// within the second.
		if rec.pending == nil {
			rec.pending = &pc
		}
		return
	}

	if rec.pending != nil {
		c.applyClose(rec, *rec.pending)
		rec.pending = nil
	}
	c.applyClose(rec, pc)

	if rec.sockRefs <= 0 {
		delete(c.records, st.key)
	}
}

// applyClose folds one close observation into the edge. Only the first
// close of a logical connection updates the aggregate (the twin socket
// reports mirrored counters for the same connection).
func (c *Correlator) applyClose(rec *connRecord, pc pendingClose) {
	if rec.closed || !rec.materialized {
		return
	}
	sent, recv := pc.sent, pc.recv
	mirror := false
	switch {
	case pc.sockID == rec.clientSock:
		mirror = false
	case pc.sockID == rec.serverSock:
		mirror = true
	case pc.dir == dirOutbound:
		mirror = false
	default:
		mirror = true
	}
	if mirror {
		sent, recv = recv, sent
	}
	c.store.ConnectionClosed(rec.edgeID, sent, recv, pc.at, !rec.bytesDone)
	c.store.EdgeRTTSample(rec.edgeID, pc.rttUs, pc.at)
	if c.rec != nil {
		c.rec.EdgeClosed(rec.edgeID, sent, recv, pc.rttUs, pc.at)
	}
	rec.bytesDone = true
	rec.closed = true
}

// noteFailedConnect records an outbound connect that never established.
func (c *Correlator) noteFailedConnect(st *sockState, ev model.ConnEvent) {
	if st.dir != dirOutbound || !st.dst.IsValid() || st.dst.Addr().IsUnspecified() {
		return
	}
	// Byte counters or an RTT estimate prove the handshake actually
	// completed — we only missed the establish event (ring overflow).
	// A real connection must not be reported as a failed connect.
	if ev.BytesSent > 0 || ev.BytesRecv > 0 || ev.SRTTMicros > 0 {
		return
	}
	c.stats.FailedConns++
	info := c.resolver.Resolve(st.pid, st.comm)
	clientSpec := c.specForProcess(info, "")

	var dstSpec graph.NodeSpec
	if nodeID, ok := c.lookupAddr(st.dst.Addr()); ok {
		// A known container address: attribute the failure to that
		// service without disturbing its stored identity.
		dstSpec = graph.NodeSpec{ID: nodeID}
	} else {
		dstSpec = specForExternal(st.dst.Addr())
	}
	edgeID := c.store.ObserveFailure(clientSpec, dstSpec, st.dst.Port(), ev.Time)
	c.store.EdgeRetrans(edgeID, st.preRetrans, ev.Time)
	c.store.EdgeResets(edgeID, st.preResets, ev.Time)
	if c.rec != nil {
		c.rec.EdgeFailure(edgeID, ev.Time)
		if st.preRetrans > 0 {
			c.rec.EdgeRetrans(edgeID, st.preRetrans, ev.Time)
		}
		if st.preResets > 0 {
			c.rec.EdgeResets(edgeID, st.preResets, ev.Time)
		}
	}
}

func (c *Correlator) lookupAddr(a netip.Addr) (string, bool) {
	c.addrMu.Lock()
	defer c.addrMu.Unlock()
	id, ok := c.addrIndex[a]
	return id, ok
}

// Tick drives deadline-based materialization and stale-state sweeping.
func (c *Correlator) Tick(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for key, rec := range c.records {
		if rec.established && !rec.materialized && !now.Before(rec.deadline) {
			c.tryMaterialize(rec, now, true)
		}
		if rec.materialized && rec.pending != nil {
			c.applyClose(rec, *rec.pending)
			rec.pending = nil
		}
		if rec.materialized && rec.closed && rec.sockRefs <= 0 {
			delete(c.records, key)
			continue
		}
		if c.idleTTL > 0 && now.Sub(rec.lastTouch) > c.idleTTL {
			c.dropRecord(key, rec, now)
		}
	}
	if c.idleTTL > 0 {
		for id, st := range c.socks {
			if now.Sub(st.lastTouch) > c.idleTTL {
				delete(c.socks, id)
			}
		}
	}
	c.stats.LiveSockets = len(c.socks)
	c.stats.LiveRecords = len(c.records)
}

// dropRecord removes tracking state for a record, releasing the edge's
// active-connection count if the record materialized but never observed
// a close (lost close event, or a connection outliving the idle TTL).
func (c *Correlator) dropRecord(key connKey, rec *connRecord, at time.Time) {
	if rec.materialized && !rec.closed {
		c.store.ConnectionClosed(rec.edgeID, 0, 0, at, false)
		if c.rec != nil {
			c.rec.EdgeExpired(rec.edgeID, at)
		}
		rec.closed = true
	}
	delete(c.records, key)
}

// Listener is one listening socket found by a scan.
type Listener struct {
	PID  uint32
	Comm string
	Addr netip.Addr
	Port uint16
}

// SyncListeners applies a complete listening-socket scan: each owning
// node gets exactly the scanned ports, everything else loses its ports.
// It deliberately takes no correlator lock: resolution may hit the live
// /proc, and the graph store synchronizes itself.
func (c *Correlator) SyncListeners(listeners []Listener, at time.Time) {
	byNode := make(map[string]*graph.ListenerSet)
	for _, l := range listeners {
		info := c.resolver.Resolve(l.PID, l.Comm)
		spec := c.specForProcess(info, addrString(l.Addr))
		set, ok := byNode[spec.ID]
		if !ok {
			set = &graph.ListenerSet{Spec: spec}
			byNode[spec.ID] = set
		}
		set.Ports = append(set.Ports, l.Port)
	}
	sets := make([]graph.ListenerSet, 0, len(byNode))
	for _, set := range byNode {
		sets = append(sets, *set)
	}
	c.store.SyncListeners(sets, at)
}

// Stats returns a copy of the current counters.
func (c *Correlator) Stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stats
}

func (c *Correlator) sock(id uint64, at time.Time) *sockState {
	st, ok := c.socks[id]
	if !ok {
		st = &sockState{lastTouch: at}
		c.socks[id] = st
	}
	st.lastTouch = at
	return st
}

func (c *Correlator) attachSock(st *sockState, key connKey, at time.Time) *connRecord {
	if st.hasKey && st.key != key {
		// The kernel reused a socket address whose close event we lost.
		// Detach from the stale record and reset the stale identity: a
		// different tuple is a different connection, and inherited
		// pid/comm/direction would misattribute it. Callers that know
		// the real identity (accept) assign it after this call.
		c.detachSock(st, at)
		st.dir = dirUnknown
		st.pid = 0
		st.comm = ""
		st.established = false
		st.preRetrans = 0
		st.preResets = 0
	}
	rec, ok := c.records[key]
	if !ok {
		rec = &connRecord{key: key, lastTouch: at}
		c.records[key] = rec
	}
	rec.lastTouch = at
	if !st.hasKey {
		st.key = key
		st.hasKey = true
		rec.sockRefs++
	}
	return rec
}

func (c *Correlator) markEstablished(rec *connRecord, at time.Time) {
	if rec.established {
		return
	}
	rec.established = true
	rec.establishedAt = at
	rec.deadline = at.Add(c.grace)
}

func (c *Correlator) tryMaterialize(rec *connRecord, now time.Time, force bool) {
	if rec.materialized || !rec.established {
		return
	}
	bothKnown := rec.clientSock != 0 && rec.serverSock != 0
	if !bothKnown && !force && now.Before(rec.deadline) {
		return
	}

	if !rec.oriented {
		switch {
		case rec.hasHint:
			rec.server = rec.hintServerLocal
			rec.client = otherEnd(rec.key, rec.hintServerLocal)
		case rec.key.a.Port() <= rec.key.b.Port():
			// Last resort: the lower port is more likely the server.
			rec.server = rec.key.a
			rec.client = rec.key.b
		default:
			rec.server = rec.key.b
			rec.client = rec.key.a
		}
		rec.oriented = true
	}

	var clientSpec, serverSpec graph.NodeSpec
	if rec.clientSock != 0 {
		info := c.resolver.Resolve(rec.clientPID, rec.clientComm)
		clientSpec = c.specForProcess(info, addrString(rec.client.Addr()))
	} else {
		clientSpec = specForExternal(rec.client.Addr())
	}
	if rec.serverSock != 0 {
		info := c.resolver.Resolve(rec.serverPID, rec.serverComm)
		serverSpec = c.specForProcess(info, addrString(rec.server.Addr()))
	} else {
		serverSpec = specForExternal(rec.server.Addr())
	}

	rec.edgeID = c.store.ObserveConnection(clientSpec, serverSpec, rec.server.Port(), rec.establishedAt)
	rec.materialized = true

	c.store.EdgeRTTSample(rec.edgeID, rec.connectRTTUs, rec.establishedAt)
	c.store.EdgeRetrans(rec.edgeID, rec.preRetrans, rec.establishedAt)
	c.store.EdgeResets(rec.edgeID, rec.preResets, rec.establishedAt)
	if c.rec != nil {
		c.rec.EdgeOpened(rec.edgeID, rec.establishedAt)
		if rec.connectRTTUs > 0 {
			c.rec.EdgeRTT(rec.edgeID, rec.connectRTTUs, rec.establishedAt)
		}
		if rec.preRetrans > 0 {
			c.rec.EdgeRetrans(rec.edgeID, rec.preRetrans, rec.establishedAt)
		}
		if rec.preResets > 0 {
			c.rec.EdgeResets(rec.edgeID, rec.preResets, rec.establishedAt)
		}
	}
	rec.preRetrans = 0
	rec.preResets = 0

	if rec.pending != nil {
		c.applyClose(rec, *rec.pending)
		rec.pending = nil
	}
}

func otherEnd(key connKey, one netip.AddrPort) netip.AddrPort {
	if key.a == one {
		return key.b
	}
	return key.a
}

func (c *Correlator) specForProcess(info model.ProcessInfo, addr string) graph.NodeSpec {
	spec := c.buildSpec(info, addr)
	// Remember the association for lifecycle attribution after the
	// process is gone.
	c.rememberPidNode(info.PID, spec.ID)
	return spec
}

func (c *Correlator) buildSpec(info model.ProcessInfo, addr string) graph.NodeSpec {
	if info.ContainerID != "" {
		short := info.ContainerID
		if len(short) > 12 {
			short = short[:12]
		}
		// Fired for every containerized observation on purpose: the
		// enricher deduplicates, and re-enqueueing is what retries a
		// lookup that failed transiently (traffic-driven retry).
		if c.onContainer != nil {
			c.onContainer(info.ContainerID)
		}
		// Container addresses identify one network namespace, so they
		// are usable for failed-connect attribution.
		if addr != "" {
			if a, err := netip.ParseAddr(addr); err == nil && !a.IsLoopback() && !a.IsUnspecified() {
				c.addrMu.Lock()
				c.addrIndex[a] = "container:" + short
				c.addrMu.Unlock()
			}
		}
		return graph.NodeSpec{
			ID:          "container:" + short,
			Kind:        graph.NodeContainer,
			Label:       short,
			Exe:         info.Exe,
			ContainerID: info.ContainerID,
			PID:         info.PID,
			Addr:        addr,
		}
	}
	if info.Exe != "" {
		return graph.NodeSpec{
			ID:    "proc:" + info.Exe,
			Kind:  graph.NodeProcess,
			Label: path.Base(info.Exe),
			Exe:   info.Exe,
			PID:   info.PID,
			Addr:  addr,
		}
	}
	label := info.Comm
	if label == "" {
		label = "unknown"
	}
	return graph.NodeSpec{
		ID:    "proc:comm:" + label,
		Kind:  graph.NodeProcess,
		Label: label,
		PID:   info.PID,
		Addr:  addr,
	}
}

func specForExternal(addr netip.Addr) graph.NodeSpec {
	s := addr.String()
	return graph.NodeSpec{
		ID:    "ext:" + s,
		Kind:  graph.NodeExternal,
		Label: s,
		Addr:  s,
	}
}

func addrString(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.String()
}

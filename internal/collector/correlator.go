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
	key         connKey
	hasKey      bool
	established bool
	lastTouch   time.Time
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
	at         time.Time
}

// Stats are exported through /api/meta.
type Stats struct {
	Events       uint64 `json:"events"`
	OpenEvents   uint64 `json:"openEvents"`
	AcceptEvents uint64 `json:"acceptEvents"`
	EstabEvents  uint64 `json:"establishedEvents"`
	CloseEvents  uint64 `json:"closeEvents"`
	LiveSockets  int    `json:"liveSockets"`
	LiveRecords  int    `json:"liveRecords"`
}

// Correlator is safe for concurrent use; in practice one goroutine feeds
// HandleEvent/Tick and others read Stats.
type Correlator struct {
	mu       sync.Mutex
	store    *graph.Store
	resolver ProcessResolver
	grace    time.Duration
	idleTTL  time.Duration
	// onContainer fires (outside any hot path guarantees, but under mu)
	// the first time a container id is seen, for async name enrichment.
	onContainer func(containerID string)

	socks          map[uint64]*sockState
	records        map[connKey]*connRecord
	seenContainers map[string]struct{}
	stats          Stats
}

// Option configures a Correlator.
type Option func(*Correlator)

// WithGracePeriod sets how long a one-sided connection waits for its
// other half before being attributed to an external endpoint.
func WithGracePeriod(d time.Duration) Option {
	return func(c *Correlator) { c.grace = d }
}

// WithContainerHook registers a callback fired once per newly seen
// container id.
func WithContainerHook(fn func(containerID string)) Option {
	return func(c *Correlator) { c.onContainer = fn }
}

// WithIdleTTL sets how long stale tracking state survives lost close
// events before being swept.
func WithIdleTTL(d time.Duration) Option {
	return func(c *Correlator) { c.idleTTL = d }
}

func New(store *graph.Store, resolver ProcessResolver, opts ...Option) *Correlator {
	c := &Correlator{
		store:          store,
		resolver:       resolver,
		grace:          time.Second,
		idleTTL:        time.Hour,
		socks:          make(map[uint64]*sockState),
		records:        make(map[connKey]*connRecord),
		seenContainers: make(map[string]struct{}),
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
	}
	c.stats.LiveSockets = len(c.socks)
	c.stats.LiveRecords = len(c.records)
}

func (c *Correlator) handleOpen(ev model.ConnEvent) {
	// connect() in process context. The source port may not be assigned
	// yet, so the tuple is not trusted until EventEstablished.
	st := c.sock(ev.SockID, ev.Time)
	st.dir = dirOutbound
	st.pid = ev.PID
	st.comm = ev.Comm
}

func (c *Correlator) handleAccept(ev model.ConnEvent) {
	st := c.sock(ev.SockID, ev.Time)
	st.dir = dirInbound
	st.pid = ev.PID
	st.comm = ev.Comm

	key := canonKey(ev.Src, ev.Dst)
	rec := c.attachSock(st, key, ev.Time)
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
		// Failed connect that never established; no record was created.
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
		sent: ev.BytesSent, recv: ev.BytesRecv, at: ev.Time,
	}

	if !rec.established {
		// Never handshaked (reset before establishment); no edge exists.
		if rec.sockRefs <= 0 {
			delete(c.records, st.key)
		}
		return
	}

	if !rec.materialized {
		if rec.sockRefs > 0 {
			// The twin socket is still live and may yet identify itself
			// (accept can trail the client's close). Stash and wait for
			// the twin or the grace deadline.
			if rec.pending == nil {
				rec.pending = &pc
			}
			return
		}
		// Nothing else is coming: attribute with what we have.
		c.tryMaterialize(rec, ev.Time, true)
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
	rec.bytesDone = true
	rec.closed = true
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
			if rec.sockRefs <= 0 {
				delete(c.records, key)
				continue
			}
		}
		if c.idleTTL > 0 && now.Sub(rec.lastTouch) > c.idleTTL {
			delete(c.records, key)
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

// ObserveListen reports a listening socket discovered by the procfs
// scanner.
func (c *Correlator) ObserveListen(pid uint32, comm string, addr netip.Addr, port uint16, at time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	info := c.resolver.Resolve(pid, comm)
	spec := c.specForProcess(info, addrString(addr))
	c.store.ObserveListen(spec, port, at)
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
	if info.ContainerID != "" {
		short := info.ContainerID
		if len(short) > 12 {
			short = short[:12]
		}
		if _, seen := c.seenContainers[info.ContainerID]; !seen {
			c.seenContainers[info.ContainerID] = struct{}{}
			if c.onContainer != nil {
				c.onContainer(info.ContainerID)
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

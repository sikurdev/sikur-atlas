package collector

import (
	"net/netip"
	"time"

	"github.com/sikurdev/sikur-atlas/internal/graph"
	"github.com/sikurdev/sikur-atlas/internal/model"
)

// SeedConn is one established TCP socket found by the startup scan of
// the kernel's socket tables (one side of a connection; a local↔local
// connection contributes two of these with mirrored tuples).
type SeedConn struct {
	PID    uint32 // 0 = unattributable (no process found holding the socket)
	Comm   string
	Local  netip.AddrPort
	Remote netip.AddrPort
	// LocalListen: a listener in the same network namespace covers
	// Local — kernel evidence that this half is the accepted side.
	LocalListen bool
}

// seedRecord tracks one standing connection discovered by the startup
// scan until it closes, expires, or its tuple is reused by a live
// connection. Unlike live records, seeds are exempt from the idle TTL:
// every scan re-verifies them against the kernel's socket table.
type seedRecord struct {
	edgeID string
	// client/server are the oriented endpoints; a close event's Src (the
	// closing socket's local end) is compared against server to decide
	// byte-counter mirroring.
	client netip.AddrPort
	server netip.AddrPort
}

// SeedConnections installs connections that were already established
// when the agent started, discovered from the kernel's socket tables
// across all scanned network namespaces. Call exactly once, after the
// BPF programs attached (so every later close is observed) and with the
// event pipeline already running.
//
// Rules, in order:
//   - halves are merged by canonical 4-tuple, like live records;
//   - a tuple already tracked live (established between BPF attach and
//     the table read) is skipped — the events own it;
//   - a tuple whose close event already arrived while the scan ran
//     (orphan close) is skipped — the connection is gone;
//   - direction comes from listener evidence (the half covered by a
//     same-namespace listener is the server); with no listener evidence
//     the lower port is taken as the server and counted in
//     SeedDirHeuristic;
//   - a half with no owning process resolves to an external node by
//     address — stated as unattributed, never guessed.
func (c *Correlator) SeedConnections(conns []SeedConn, at time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	type merged struct {
		a, b *SeedConn // up to two halves
	}
	byKey := make(map[connKey]*merged)
	order := make([]connKey, 0, len(conns))
	for i := range conns {
		sc := &conns[i]
		key := canonKey(sc.Local, sc.Remote)
		m, ok := byKey[key]
		if !ok {
			m = &merged{a: sc}
			byKey[key] = m
			order = append(order, key)
			continue
		}
		if m.b == nil && m.a.Local != sc.Local {
			m.b = sc
		}
		// A third sighting of the same tuple (or a duplicate row) adds
		// nothing truthful; the first two halves win.
	}

	for _, key := range order {
		m := byKey[key]
		if _, tracked := c.records[key]; tracked {
			continue // live events already own this tuple
		}
		if _, seeded := c.seeds[key]; seeded {
			continue
		}
		if _, closed := c.orphanCloses[key]; closed {
			continue // closed while the scan was running
		}

		client, server, heuristic := orientSeed(m.a, m.b)
		if heuristic {
			c.stats.SeedDirHeuristic++
		}

		clientSpec := c.seedEndpointSpec(client)
		serverSpec := c.seedEndpointSpec(server)
		edgeID := c.store.SeedConnection(clientSpec, serverSpec, server.half.Local.Port(), at)
		c.seeds[key] = &seedRecord{
			edgeID: edgeID,
			client: client.half.Local,
			server: server.half.Local,
		}
		c.stats.SeededConns++
		if c.rec != nil {
			c.rec.EdgeActive(edgeID, +1, at)
		}
	}

	// The orphan-close buffer only exists to cover the window between
	// BPF attach and this first seed pass; from here on unknown-socket
	// closes are matched against seeds directly.
	c.seeded = true
	c.orphanCloses = nil
	c.stats.LiveSeeds = len(c.seeds)
}

// seedEndpoint pairs one oriented half with whether it is locally
// attributable.
type seedEndpoint struct {
	half  *SeedConn
	local bool // an owning process was found for this half
}

// orientSeed decides which half is the client and which the server.
// The second return half may be synthesized from the first's remote end
// when only one half was found (the peer is off-host or unattributable).
func orientSeed(a, b *SeedConn) (client, server seedEndpoint, heuristic bool) {
	if b == nil {
		// One half only: its listener coverage decides its own role; the
		// peer is whatever the tuple says it is.
		peer := &SeedConn{Local: a.Remote, Remote: a.Local}
		if a.LocalListen {
			return seedEndpoint{half: peer}, seedEndpoint{half: a, local: true}, false
		}
		return seedEndpoint{half: a, local: true}, seedEndpoint{half: peer}, false
	}
	ea := seedEndpoint{half: a, local: a.PID != 0}
	eb := seedEndpoint{half: b, local: b.PID != 0}
	switch {
	case a.LocalListen && !b.LocalListen:
		return eb, ea, false
	case b.LocalListen && !a.LocalListen:
		return ea, eb, false
	}
	// No usable listener evidence (none, or both ends listen on their
	// ports): fall back to the same last resort the live correlator uses
	// for connections that never identified themselves — the lower port
	// is more likely the server.
	if a.Local.Port() <= b.Local.Port() {
		return eb, ea, true
	}
	return ea, eb, true
}

// seedEndpointSpec resolves one seed endpoint into a node spec: an
// attributed process resolves through /proc like any live observation;
// anything else is an external endpoint by address.
func (c *Correlator) seedEndpointSpec(e seedEndpoint) graph.NodeSpec {
	if e.local && e.half.PID != 0 {
		info := c.resolver.Resolve(e.half.PID, e.half.Comm)
		return c.specForProcess(info, addrString(e.half.Local.Addr()))
	}
	return specForExternal(e.half.Local.Addr())
}

// closeSeed matches a close event that no tracked socket claims against
// the seeded connections. Returns true when the event was consumed.
// Caller holds c.mu.
func (c *Correlator) closeSeed(ev model.ConnEvent) bool {
	if !ev.Src.IsValid() || !ev.Dst.IsValid() || ev.Dst.Addr().IsUnspecified() {
		return false // listen-socket teardown or half-formed tuple
	}
	key := canonKey(ev.Src, ev.Dst)
	seed, ok := c.seeds[key]
	if !ok {
		if !c.seeded {
			c.noteOrphanClose(key)
		}
		return false
	}
	delete(c.seeds, key)
	c.stats.SeedClosed++
	c.stats.LiveSeeds = len(c.seeds)

	// Both halves report the same lifetime counters; the twin half's
	// close finds the seed gone and is a no-op, so bytes fold exactly
	// once. The counters are from the closing socket's perspective:
	// mirror them when that socket is the server side.
	sent, recv := ev.BytesSent, ev.BytesRecv
	if ev.Src == seed.server {
		sent, recv = recv, sent
	}
	c.store.SeedConnectionClosed(seed.edgeID, sent, recv, ev.Time, true)
	c.store.EdgeRTTSample(seed.edgeID, ev.SRTTMicros, ev.Time)
	if c.rec != nil {
		c.rec.EdgeClosed(seed.edgeID, sent, recv, ev.SRTTMicros, ev.Time)
	}
	return true
}

// expireSeedLocked releases a seed whose socket is gone without an
// observed close (lost event), or whose tuple a new live connection is
// about to reuse. Caller holds c.mu.
func (c *Correlator) expireSeedLocked(key connKey, at time.Time) {
	seed, ok := c.seeds[key]
	if !ok {
		return
	}
	delete(c.seeds, key)
	c.stats.SeedExpired++
	c.stats.LiveSeeds = len(c.seeds)
	c.store.SeedConnectionClosed(seed.edgeID, 0, 0, at, false)
	if c.rec != nil {
		c.rec.EdgeExpired(seed.edgeID, at)
	}
}

// maxOrphanCloses bounds the pre-seed close buffer; a host churning
// through more connections during the one-off seed scan simply risks a
// few seeds lingering until the next scan re-verifies them.
const maxOrphanCloses = 8192

// noteOrphanClose remembers a close that matched nothing, so the seed
// pass does not resurrect a connection that died while the scan ran.
// Only used before the first seed pass. Caller holds c.mu.
func (c *Correlator) noteOrphanClose(key connKey) {
	if len(c.orphanCloses) >= maxOrphanCloses {
		return
	}
	if c.orphanCloses == nil {
		c.orphanCloses = make(map[connKey]struct{})
	}
	c.orphanCloses[key] = struct{}{}
}

// ReconcileSeeds re-verifies the surviving seeds against a fresh socket
// table scan: a seed whose tuple no longer appears established lost its
// close event and is expired. It never adds seeds — connections opened
// after startup are the event stream's to track.
func (c *Correlator) ReconcileSeeds(current []SeedConn, at time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.seeds) == 0 {
		return
	}
	live := make(map[connKey]struct{}, len(current))
	for i := range current {
		live[canonKey(current[i].Local, current[i].Remote)] = struct{}{}
	}
	for key := range c.seeds {
		if _, ok := live[key]; !ok {
			c.expireSeedLocked(key, at)
		}
	}
}

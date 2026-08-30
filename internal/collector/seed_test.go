package collector

import (
	"testing"
	"time"

	"github.com/sikurdev/sikur-atlas/internal/graph"
	"github.com/sikurdev/sikur-atlas/internal/model"
)

// seedPair returns the two halves of one local↔local connection:
// client 10.0.0.2:50000 → server 10.0.0.3:8000 (server listens).
func seedPair() []SeedConn {
	return []SeedConn{
		{PID: 100, Comm: "client", Local: ap("10.0.0.2", 50000), Remote: ap("10.0.0.3", 8000)},
		{PID: 200, Comm: "server", Local: ap("10.0.0.3", 8000), Remote: ap("10.0.0.2", 50000), LocalListen: true},
	}
}

func seedResolver() fakeResolver {
	return fakeResolver{
		100: {PID: 100, Comm: "client", Exe: "/bin/client"},
		200: {PID: 200, Comm: "server", Exe: "/bin/server"},
	}
}

func TestSeedMergesHalvesIntoOneEdge(t *testing.T) {
	c, store := newTestCorrelator(seedResolver())
	c.SeedConnections(seedPair(), base)

	snap := store.Snapshot()
	if len(snap.Edges) != 1 {
		t.Fatalf("want 1 edge from two seeded halves, got %d: %+v", len(snap.Edges), snap.Edges)
	}
	e := snap.Edges[0]
	if e.Src != "proc:/bin/client" || e.Dst != "proc:/bin/server" || e.DstPort != 8000 {
		t.Fatalf("wrong orientation: %+v", e)
	}
	if e.ActiveConns != 1 || e.SeededConns != 1 {
		t.Fatalf("want active=1 seeded=1, got active=%d seeded=%d", e.ActiveConns, e.SeededConns)
	}
	if e.Connections != 0 {
		t.Fatalf("seeded connection must not count as an observed open, got %d", e.Connections)
	}
	if got := c.Stats().SeededConns; got != 1 {
		t.Fatalf("stats.SeededConns = %d, want 1", got)
	}
	if got := c.Stats().SeedDirHeuristic; got != 0 {
		t.Fatalf("listener evidence present, but SeedDirHeuristic = %d", got)
	}
}

func TestSeedSingleHalfOutbound(t *testing.T) {
	c, store := newTestCorrelator(seedResolver())
	c.SeedConnections([]SeedConn{
		{PID: 100, Comm: "client", Local: ap("192.168.1.5", 43210), Remote: ap("93.184.216.34", 443)},
	}, base)

	e := edgeByID(t, store, "proc:/bin/client->ext:93.184.216.34:443")
	if e.ActiveConns != 1 || e.SeededConns != 1 || e.Connections != 0 {
		t.Fatalf("unexpected counters: %+v", e)
	}
}

func TestSeedSingleHalfInbound(t *testing.T) {
	c, store := newTestCorrelator(seedResolver())
	c.SeedConnections([]SeedConn{
		{PID: 200, Comm: "server", Local: ap("192.168.1.5", 8000), Remote: ap("203.0.113.9", 55000), LocalListen: true},
	}, base)

	e := edgeByID(t, store, "ext:203.0.113.9->proc:/bin/server:8000")
	if e.ActiveConns != 1 || e.SeededConns != 1 {
		t.Fatalf("unexpected counters: %+v", e)
	}
}

func TestSeedUnattributedHalfBecomesExternal(t *testing.T) {
	c, store := newTestCorrelator(seedResolver())
	c.SeedConnections([]SeedConn{
		{PID: 100, Comm: "client", Local: ap("10.0.0.2", 50000), Remote: ap("10.0.0.3", 8000)},
		{PID: 0, Local: ap("10.0.0.3", 8000), Remote: ap("10.0.0.2", 50000), LocalListen: true},
	}, base)

	// The server half exists in the kernel table but no owning process
	// was found: stated as unattributed (external), never guessed.
	e := edgeByID(t, store, "proc:/bin/client->ext:10.0.0.3:8000")
	if e.ActiveConns != 1 || e.SeededConns != 1 {
		t.Fatalf("unexpected counters: %+v", e)
	}
}

func TestSeedDirectionHeuristicWithoutListenerEvidence(t *testing.T) {
	c, store := newTestCorrelator(seedResolver())
	c.SeedConnections([]SeedConn{
		{PID: 100, Comm: "client", Local: ap("10.0.0.2", 50000), Remote: ap("10.0.0.3", 8000)},
		{PID: 200, Comm: "server", Local: ap("10.0.0.3", 8000), Remote: ap("10.0.0.2", 50000)},
	}, base)

	// No listener evidence: lower port taken as the server, counted.
	e := edgeByID(t, store, "proc:/bin/client->proc:/bin/server:8000")
	if e.SeededConns != 1 {
		t.Fatalf("unexpected counters: %+v", e)
	}
	if got := c.Stats().SeedDirHeuristic; got != 1 {
		t.Fatalf("stats.SeedDirHeuristic = %d, want 1", got)
	}
}

func TestSeedCloseReconciles(t *testing.T) {
	c, store := newTestCorrelator(seedResolver())
	c.SeedConnections(seedPair(), base)

	// The client half closes: an untracked sock id, a known tuple, and
	// the lifetime byte counters ride along.
	closeEv := ev(model.EventClose, 999, 0, "", ap("10.0.0.2", 50000), ap("10.0.0.3", 8000), 5000)
	closeEv.BytesSent = 1000
	closeEv.BytesRecv = 5000
	closeEv.SRTTMicros = 1500
	c.HandleEvent(closeEv)

	e := edgeByID(t, store, "proc:/bin/client->proc:/bin/server:8000")
	if e.ActiveConns != 0 || e.SeededConns != 0 {
		t.Fatalf("close must release the seed: %+v", e)
	}
	if e.BytesSent != 1000 || e.BytesRecv != 5000 {
		t.Fatalf("close bytes not folded: %+v", e)
	}
	if e.LastRTTUs != 1500 {
		t.Fatalf("close RTT not sampled: %+v", e)
	}
	if got := c.Stats().SeedClosed; got != 1 {
		t.Fatalf("stats.SeedClosed = %d, want 1", got)
	}

	// The twin (server) half closes too: the seed is gone, nothing
	// double-counts.
	twin := ev(model.EventClose, 998, 0, "", ap("10.0.0.3", 8000), ap("10.0.0.2", 50000), 5001)
	twin.BytesSent = 5000
	twin.BytesRecv = 1000
	c.HandleEvent(twin)
	e = edgeByID(t, store, "proc:/bin/client->proc:/bin/server:8000")
	if e.ActiveConns != 0 || e.BytesSent != 1000 || e.BytesRecv != 5000 {
		t.Fatalf("twin close double-counted: %+v", e)
	}
}

func TestSeedCloseFromServerHalfMirrorsBytes(t *testing.T) {
	c, store := newTestCorrelator(seedResolver())
	c.SeedConnections(seedPair(), base)

	// The server half closes first: its counters are from the server's
	// perspective and must mirror onto the client→server edge.
	closeEv := ev(model.EventClose, 999, 0, "", ap("10.0.0.3", 8000), ap("10.0.0.2", 50000), 5000)
	closeEv.BytesSent = 5000 // server sent 5000 = client received 5000
	closeEv.BytesRecv = 1000
	c.HandleEvent(closeEv)

	e := edgeByID(t, store, "proc:/bin/client->proc:/bin/server:8000")
	if e.BytesSent != 1000 || e.BytesRecv != 5000 {
		t.Fatalf("server-half close not mirrored: %+v", e)
	}
}

func TestSeedSkipsTupleAlreadyTrackedLive(t *testing.T) {
	c, store := newTestCorrelator(seedResolver())

	// A connection establishes between BPF attach and the table read:
	// the events own it.
	c.HandleEvent(ev(model.EventOpen, 1, 100, "client", ap("10.0.0.2", 0), ap("10.0.0.3", 8000), 0))
	c.HandleEvent(ev(model.EventEstablished, 1, 0, "", ap("10.0.0.2", 50000), ap("10.0.0.3", 8000), 10))
	c.Tick(base.Add(2 * time.Second)) // grace expires, edge materializes

	c.SeedConnections(seedPair(), base.Add(3*time.Second))

	e := edgeByID(t, store, "proc:/bin/client->ext:10.0.0.3:8000")
	if e.ActiveConns != 1 || e.SeededConns != 0 || e.Connections != 1 {
		t.Fatalf("seed must not double a live-tracked tuple: %+v", e)
	}
	if got := c.Stats().SeededConns; got != 0 {
		t.Fatalf("stats.SeededConns = %d, want 0", got)
	}
}

func TestSeedSkipsTupleClosedDuringScan(t *testing.T) {
	c, store := newTestCorrelator(seedResolver())

	// The connection dies while the scan is still walking /proc: its
	// close (unknown sock id, no seed yet) must inoculate the seed pass.
	c.HandleEvent(ev(model.EventClose, 999, 0, "", ap("10.0.0.2", 50000), ap("10.0.0.3", 8000), 0))
	c.SeedConnections(seedPair(), base.Add(time.Second))

	if len(store.Snapshot().Edges) != 0 {
		t.Fatalf("stale seed created for a tuple that closed mid-scan: %+v", store.Snapshot().Edges)
	}
	if got := c.Stats().SeededConns; got != 0 {
		t.Fatalf("stats.SeededConns = %d, want 0", got)
	}
}

func TestOrphanCloseBufferOnlyPreSeed(t *testing.T) {
	c, store := newTestCorrelator(seedResolver())
	c.SeedConnections(nil, base)

	// After the seed pass the buffer is retired: a stray close for an
	// unknown tuple is a no-op, not a memory.
	c.HandleEvent(ev(model.EventClose, 999, 0, "", ap("10.0.0.2", 50000), ap("10.0.0.3", 8000), 0))
	if c.orphanCloses != nil {
		t.Fatal("orphan-close buffer must be dropped after seeding")
	}
	if len(store.Snapshot().Edges) != 0 {
		t.Fatalf("unexpected edges: %+v", store.Snapshot().Edges)
	}
}

func TestSeedExpiredWhenLiveConnectionReusesTuple(t *testing.T) {
	c, store := newTestCorrelator(seedResolver())
	c.SeedConnections(seedPair(), base)

	// The seeded socket dies (close event lost); the kernel reuses the
	// exact tuple for a fresh connection. Tracking both would double the
	// active count.
	c.HandleEvent(ev(model.EventOpen, 5, 100, "client", ap("10.0.0.2", 0), ap("10.0.0.3", 8000), 1000))
	c.HandleEvent(ev(model.EventEstablished, 5, 0, "", ap("10.0.0.2", 50000), ap("10.0.0.3", 8000), 1010))
	c.HandleEvent(ev(model.EventAccept, 6, 200, "server", ap("10.0.0.3", 8000), ap("10.0.0.2", 50000), 1020))

	e := edgeByID(t, store, "proc:/bin/client->proc:/bin/server:8000")
	if e.ActiveConns != 1 || e.SeededConns != 0 {
		t.Fatalf("seed not released on tuple reuse: %+v", e)
	}
	if e.Connections != 1 {
		t.Fatalf("live connection lost: %+v", e)
	}
	if got := c.Stats().SeedExpired; got != 1 {
		t.Fatalf("stats.SeedExpired = %d, want 1", got)
	}
}

func TestReconcileSeedsExpiresVanished(t *testing.T) {
	c, store := newTestCorrelator(seedResolver())
	c.SeedConnections(seedPair(), base)

	// First re-scan still sees the connection: seed survives.
	c.ReconcileSeeds(seedPair(), base.Add(30*time.Second))
	e := edgeByID(t, store, "proc:/bin/client->proc:/bin/server:8000")
	if e.ActiveConns != 1 || e.SeededConns != 1 {
		t.Fatalf("seed wrongly expired while its socket lives: %+v", e)
	}

	// Second re-scan: the socket is gone and no close was observed.
	c.ReconcileSeeds(nil, base.Add(60*time.Second))
	e = edgeByID(t, store, "proc:/bin/client->proc:/bin/server:8000")
	if e.ActiveConns != 0 || e.SeededConns != 0 {
		t.Fatalf("vanished seed not expired: %+v", e)
	}
	if got := c.Stats().SeedExpired; got != 1 {
		t.Fatalf("stats.SeedExpired = %d, want 1", got)
	}
}

func TestReconcileNeverAddsSeeds(t *testing.T) {
	c, store := newTestCorrelator(seedResolver())
	c.SeedConnections(nil, base)
	c.ReconcileSeeds(seedPair(), base.Add(30*time.Second))
	if len(store.Snapshot().Edges) != 0 {
		t.Fatalf("reconcile must never add seeds: %+v", store.Snapshot().Edges)
	}
}

func TestSeedRecordedInHistoryGauge(t *testing.T) {
	rec := &captureRecorder{}
	store := graph.NewStore()
	c := New(store, seedResolver(), WithGracePeriod(time.Second), WithRecorder(rec))

	c.SeedConnections(seedPair(), base)
	if len(rec.active) != 1 || rec.active[0].delta != 1 {
		t.Fatalf("seed must record EdgeActive(+1), got %+v", rec.active)
	}

	closeEv := ev(model.EventClose, 999, 0, "", ap("10.0.0.2", 50000), ap("10.0.0.3", 8000), 5000)
	closeEv.BytesSent = 7
	c.HandleEvent(closeEv)
	if len(rec.closed) != 1 || rec.closed[0].sent != 7 {
		t.Fatalf("seed close must record EdgeClosed, got %+v", rec.closed)
	}
	if len(rec.opened) != 0 {
		t.Fatalf("a seed must never record an open, got %+v", rec.opened)
	}
}

func TestSeedExpiryRecordedAsExpired(t *testing.T) {
	rec := &captureRecorder{}
	store := graph.NewStore()
	c := New(store, seedResolver(), WithRecorder(rec))

	c.SeedConnections(seedPair(), base)
	c.ReconcileSeeds(nil, base.Add(30*time.Second))
	if len(rec.expired) != 1 {
		t.Fatalf("vanished seed must record EdgeExpired, got %+v", rec.expired)
	}
}

func TestSeedNotIdleSwept(t *testing.T) {
	c, store := newTestCorrelator(seedResolver())
	c.SeedConnections(seedPair(), base)

	// Far past the idle TTL: live tracking state would be swept, but a
	// seed is re-verified by scans, not by silence.
	c.Tick(base.Add(3 * time.Hour))
	e := edgeByID(t, store, "proc:/bin/client->proc:/bin/server:8000")
	if e.ActiveConns != 1 || e.SeededConns != 1 {
		t.Fatalf("seed must survive the idle sweep: %+v", e)
	}
}

// captureRecorder records the recorder calls the seed path makes.
type captureRecorder struct {
	opened []string
	closed []struct {
		id   string
		sent uint64
	}
	expired []string
	active  []struct {
		id    string
		delta int64
	}
}

func (r *captureRecorder) EdgeOpened(id string, _ time.Time) { r.opened = append(r.opened, id) }
func (r *captureRecorder) EdgeClosed(id string, sent, _ uint64, _ uint32, _ time.Time) {
	r.closed = append(r.closed, struct {
		id   string
		sent uint64
	}{id, sent})
}
func (r *captureRecorder) EdgeExpired(id string, _ time.Time)     { r.expired = append(r.expired, id) }
func (r *captureRecorder) EdgeFailure(string, time.Time)          {}
func (r *captureRecorder) EdgeResets(string, uint64, time.Time)   {}
func (r *captureRecorder) EdgeRetrans(string, uint64, time.Time)  {}
func (r *captureRecorder) EdgeRTT(string, uint32, time.Time)      {}
func (r *captureRecorder) EdgeConnects(string, uint64, time.Time) {}
func (r *captureRecorder) EdgeActive(id string, delta int64, _ time.Time) {
	r.active = append(r.active, struct {
		id    string
		delta int64
	}{id, delta})
}
func (r *captureRecorder) NodeEvent(string, string, uint32, string, time.Time) {}

func TestSeedSkipsTupleTrackedAndClosedDuringScan(t *testing.T) {
	c, store := newTestCorrelator(seedResolver())

	// A connection opens, establishes AND fully closes between BPF
	// attach and the seed pass — all observed live. The seed scan may
	// have read the socket table while it lived; it must not be
	// resurrected as a standing connection.
	c.HandleEvent(ev(model.EventOpen, 1, 100, "client", ap("10.0.0.2", 0), ap("10.0.0.3", 8000), 0))
	c.HandleEvent(ev(model.EventEstablished, 1, 0, "", ap("10.0.0.2", 50000), ap("10.0.0.3", 8000), 10))
	c.Tick(base.Add(2 * time.Second)) // materialize
	c.HandleEvent(ev(model.EventClose, 1, 0, "", ap("10.0.0.2", 50000), ap("10.0.0.3", 8000), 3000))

	c.SeedConnections(seedPair(), base.Add(4*time.Second))

	e := edgeByID(t, store, "proc:/bin/client->ext:10.0.0.3:8000")
	if e.ActiveConns != 0 || e.SeededConns != 0 {
		t.Fatalf("closed tracked connection resurrected as a seed: %+v", e)
	}
	if got := c.Stats().SeededConns; got != 0 {
		t.Fatalf("stats.SeededConns = %d, want 0", got)
	}
}

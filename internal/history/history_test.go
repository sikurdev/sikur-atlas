package history

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/sikurdev/sikur-atlas/internal/graph"
)

var t0 = time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)

func openTest(t *testing.T, g *graph.Store) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "history.db")
	s, err := Open(path, g, WithSpans(10*time.Second, 60*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func seedGraph() *graph.Store {
	g := graph.NewStore()
	curl := graph.NodeSpec{ID: "proc:/usr/bin/curl", Kind: graph.NodeProcess, Label: "curl", PID: 100}
	nginx := graph.NodeSpec{ID: "proc:/usr/sbin/nginx", Kind: graph.NodeProcess, Label: "nginx", PID: 200}
	g.ObserveConnection(curl, nginx, 8080, t0)
	g.SyncListeners([]graph.ListenerSet{{Spec: nginx, Ports: []uint16{8080}}}, t0)
	return g
}

func edgeID() string { return "proc:/usr/bin/curl->proc:/usr/sbin/nginx:8080" }

// The heart of Replay: activity in two eras must reconstruct as two
// different graph states.
func TestSnapshotAtReconstructsTwoStates(t *testing.T) {
	g := seedGraph()
	s := openTest(t, g)
	id := edgeID()

	// Era A: connections at t0.
	s.EdgeOpened(id, t0)
	s.EdgeRTT(id, 1500, t0)
	s.EdgeClosed(id, 500, 1000, 2000, t0.Add(2*time.Second))
	if err := s.Flush(t0.Add(15 * time.Second)); err != nil {
		t.Fatal(err)
	}

	// Era B: ten minutes later a different edge appears and the first is
	// silent.
	tB := t0.Add(10 * time.Minute)
	g.ObserveConnection(
		graph.NodeSpec{ID: "proc:/usr/sbin/nginx", Kind: graph.NodeProcess, Label: "nginx"},
		graph.NodeSpec{ID: "container:cache000000", Kind: graph.NodeContainer, Label: "cache"},
		6379, tB)
	id2 := "proc:/usr/sbin/nginx->container:cache000000:6379"
	s.EdgeOpened(id2, tB)
	if err := s.Flush(tB.Add(15 * time.Second)); err != nil {
		t.Fatal(err)
	}

	// State at A: only the curl->nginx edge.
	snapA, err := s.SnapshotAt(t0.Add(30*time.Second), 2*time.Minute, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapA.Edges) != 1 || snapA.Edges[0].ID != id {
		t.Fatalf("state A edges = %+v", snapA.Edges)
	}
	e := snapA.Edges[0]
	if e.Window == nil || e.Window.Opens != 1 || e.Window.Closes != 1 {
		t.Fatalf("state A window = %+v", e.Window)
	}
	if e.Window.BytesSent != 500 || e.Window.BytesRecv != 1000 {
		t.Fatalf("state A bytes = %+v", e.Window)
	}
	if e.Window.RTTAvgUs != (1500+2000)/2 || e.Window.RTTMaxUs != 2000 {
		t.Fatalf("state A rtt = %+v", e.Window)
	}
	if len(snapA.Nodes) != 2 {
		t.Fatalf("state A nodes = %+v", snapA.Nodes)
	}

	// State at B: only the nginx->cache edge (A's edge aged out of the
	// presence window).
	snapB, err := s.SnapshotAt(tB.Add(30*time.Second), 2*time.Minute, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapB.Edges) != 1 || snapB.Edges[0].ID != id2 {
		t.Fatalf("state B edges = %+v", snapB.Edges)
	}
	if snapB.Edges[0].ActiveConns != 1 {
		t.Fatalf("state B active = %d, want 1 (open, never closed)", snapB.Edges[0].ActiveConns)
	}
	hasCache := false
	for _, n := range snapB.Nodes {
		if n.ID == "container:cache000000" {
			hasCache = true
		}
		if n.ID == "proc:/usr/bin/curl" {
			t.Fatalf("curl should be absent at B: %+v", snapB.Nodes)
		}
	}
	if !hasCache {
		t.Fatalf("cache missing at B: %+v", snapB.Nodes)
	}
}

// History must survive a process restart: reopen the same file and
// reconstruct.
func TestHistorySurvivesReopen(t *testing.T) {
	g := seedGraph()
	path := filepath.Join(t.TempDir(), "history.db")
	s, err := Open(path, g, WithSpans(10*time.Second, 60*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	id := edgeID()
	s.EdgeOpened(id, t0)
	s.EdgeClosed(id, 10, 20, 900, t0.Add(time.Second))
	if err := s.Flush(t0.Add(15 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// A fresh process: no graph state carried over.
	s2, err := Open(path, graph.NewStore(), WithSpans(10*time.Second, 60*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	snap, err := s2.SnapshotAt(t0.Add(30*time.Second), 2*time.Minute, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Edges) != 1 || snap.Edges[0].Window.BytesSent != 10 {
		t.Fatalf("history lost across reopen: %+v", snap.Edges)
	}
	if len(snap.Nodes) != 2 {
		t.Fatalf("node metadata lost across reopen: %+v", snap.Nodes)
	}
	// Listen ports survive for nodes that were listening.
	for _, n := range snap.Nodes {
		if n.ID == "proc:/usr/sbin/nginx" && len(n.ListenPorts) != 1 {
			t.Fatalf("listen ports lost: %+v", n)
		}
	}
}

func TestWindowHealthMergesUnflushed(t *testing.T) {
	g := seedGraph()
	s := openTest(t, g)
	id := edgeID()

	// Flushed activity.
	s.EdgeOpened(id, t0)
	s.EdgeFailure(id, t0.Add(time.Second))
	if err := s.Flush(t0.Add(15 * time.Second)); err != nil {
		t.Fatal(err)
	}
	// Unflushed activity in the current bucket.
	s.EdgeRetrans(id, 3, t0.Add(16*time.Second))
	s.EdgeOpened(id, t0.Add(17*time.Second))

	health, err := s.WindowHealth(t0.Add(18*time.Second), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	w, ok := health[id]
	if !ok {
		t.Fatalf("no health for edge: %v", health)
	}
	if w.Opens != 2 || w.Failures != 1 || w.Retransmits != 3 {
		t.Fatalf("window = %+v", w)
	}
	if w.ActiveEnd != 2 {
		t.Fatalf("active = %d, want 2", w.ActiveEnd)
	}
}

func TestTimeline(t *testing.T) {
	g := seedGraph()
	s := openTest(t, g)
	id := edgeID()

	s.EdgeOpened(id, t0)
	s.EdgeOpened(id, t0.Add(time.Second))
	s.EdgeFailure(id, t0.Add(30*time.Second))
	if err := s.Flush(t0.Add(50 * time.Second)); err != nil {
		t.Fatal(err)
	}
	// Unflushed bucket must appear too.
	s.EdgeOpened(id, t0.Add(55*time.Second))

	series, err := s.Timeline(t0, t0.Add(time.Minute), 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(series) != 7 {
		t.Fatalf("series length = %d: %+v", len(series), series)
	}
	if series[0].Opens != 2 {
		t.Fatalf("bucket 0 = %+v", series[0])
	}
	if series[3].Failures != 1 {
		t.Fatalf("bucket 3 = %+v", series[3])
	}
	if series[5].Opens != 1 {
		t.Fatalf("unflushed bucket missing: %+v", series[5])
	}
}

// Compaction folds fine buckets into coarse ones without losing the
// ability to reconstruct (at reduced resolution).
func TestCompactPreservesHistory(t *testing.T) {
	g := seedGraph()
	s := openTest(t, g) // fine 10s, coarse 60s
	id := edgeID()

	for i := 0; i < 6; i++ {
		at := t0.Add(time.Duration(i*10) * time.Second)
		s.EdgeOpened(id, at)
		s.EdgeClosed(id, 100, 200, 1000, at.Add(time.Second))
	}
	if err := s.Flush(t0.Add(2 * time.Minute)); err != nil {
		t.Fatal(err)
	}

	// Everything is older than the fine retention now.
	s.fineRetention = time.Minute
	now := t0.Add(10 * time.Minute)
	if err := s.Compact(now); err != nil {
		t.Fatal(err)
	}

	var fineRows int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM edge_buckets WHERE span = 10`).Scan(&fineRows); err != nil {
		t.Fatal(err)
	}
	if fineRows != 0 {
		t.Fatalf("fine rows survived compaction: %d", fineRows)
	}

	snap, err := s.SnapshotAt(t0.Add(time.Minute), 2*time.Minute, 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Edges) != 1 {
		t.Fatalf("post-compaction edges = %+v", snap.Edges)
	}
	w := snap.Edges[0].Window
	if w.Opens != 6 || w.BytesSent != 600 {
		t.Fatalf("post-compaction window = %+v", w)
	}

	// Coarse retention drops ancient data.
	s.coarseRetention = time.Minute
	if err := s.Compact(t0.Add(24 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	var rows int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM edge_buckets`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Fatalf("rows past coarse retention survived: %d", rows)
	}
}

// Compaction must carry per-era listen ports into the coarse presence
// rows — Replay of old eras keeps showing what was listening then.
func TestCompactPreservesListenPorts(t *testing.T) {
	g := seedGraph()
	s := openTest(t, g) // fine 10s, coarse 60s
	id := edgeID()

	s.EdgeOpened(id, t0)
	if err := s.Flush(t0.Add(15 * time.Second)); err != nil {
		t.Fatal(err)
	}
	s.fineRetention = time.Minute
	if err := s.Compact(t0.Add(10 * time.Minute)); err != nil {
		t.Fatal(err)
	}

	snap, err := s.SnapshotAt(t0.Add(30*time.Second), 2*time.Minute, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, n := range snap.Nodes {
		if n.ID == "proc:/usr/sbin/nginx" {
			found = true
			if len(n.ListenPorts) != 1 || n.ListenPorts[0] != 8080 {
				t.Fatalf("ports lost in compaction: %+v", n)
			}
		}
	}
	if !found {
		t.Fatalf("nginx missing post-compaction: %+v", snap.Nodes)
	}
}

// A failed flush must requeue the drained buckets instead of losing the
// interval's telemetry.
func TestFlushFailureRequeues(t *testing.T) {
	g := seedGraph()
	s := openTest(t, g)
	id := edgeID()

	s.EdgeOpened(id, t0)
	s.EdgeFailure(id, t0.Add(time.Second))

	// Sabotage the schema so the flush transaction fails, then restore.
	if _, err := s.db.Exec(`ALTER TABLE edge_buckets RENAME TO edge_buckets_hidden`); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(t0.Add(15 * time.Second)); err == nil {
		t.Fatal("flush against a broken schema must error")
	}
	if _, err := s.db.Exec(`ALTER TABLE edge_buckets_hidden RENAME TO edge_buckets`); err != nil {
		t.Fatal(err)
	}

	// While unflushed, the data must still be readable (staging/requeue).
	health, err := s.WindowHealth(t0.Add(16*time.Second), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if w := health[id]; w.Opens != 1 || w.Failures != 1 {
		t.Fatalf("requeued data invisible: %+v", w)
	}

	if err := s.Flush(t0.Add(25 * time.Second)); err != nil {
		t.Fatal(err)
	}
	snap, err := s.SnapshotAt(t0.Add(30*time.Second), 2*time.Minute, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Edges) != 1 || snap.Edges[0].Window.Opens != 1 || snap.Edges[0].Window.Failures != 1 {
		t.Fatalf("telemetry lost across failed flush: %+v", snap.Edges)
	}
}

// An edge opened inside the still-open bucket must not get a keep-alive
// presence row backdated into the previous bucket.
func TestKeepAliveDoesNotBackdate(t *testing.T) {
	g := seedGraph()
	s := openTest(t, g)
	id := edgeID()

	// Open inside the CURRENT (unflushed at flush time) bucket: flush at
	// t0+15s has cutoff t0+10s, so an open at t0+12s stays in memory.
	s.EdgeOpened(id, t0.Add(12*time.Second))
	if err := s.Flush(t0.Add(15 * time.Second)); err != nil {
		t.Fatal(err)
	}

	var n int
	if err := s.db.QueryRow(
		`SELECT COUNT(*) FROM edge_buckets WHERE bucket < ?`,
		t0.Add(10*time.Second).Unix(),
	).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("edge backdated into a bucket before it existed: %d rows", n)
	}

	// The next flush persists it in its true bucket.
	if err := s.Flush(t0.Add(25 * time.Second)); err != nil {
		t.Fatal(err)
	}
	snap, err := s.SnapshotAt(t0.Add(26*time.Second), 2*time.Minute, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Edges) != 1 || snap.Edges[0].ActiveConns != 1 {
		t.Fatalf("open edge lost: %+v", snap.Edges)
	}
}

// A stale listen port must not be presented as current in a window where
// the node was not observed listening.
func TestReplayHidesStaleListenPorts(t *testing.T) {
	g := seedGraph()
	s := openTest(t, g)
	id := edgeID()

	s.EdgeOpened(id, t0)
	if err := s.Flush(t0.Add(15 * time.Second)); err != nil {
		t.Fatal(err)
	}

	// Later era: nginx stopped listening (a scan cleared its ports) but
	// its edge keeps flowing, so it is still present.
	tB := t0.Add(10 * time.Minute)
	g.SyncListeners(nil, tB)
	g.ObserveConnection(
		graph.NodeSpec{ID: "proc:/usr/bin/curl", Kind: graph.NodeProcess, Label: "curl"},
		graph.NodeSpec{ID: "proc:/usr/sbin/nginx", Kind: graph.NodeProcess, Label: "nginx"},
		8080, tB)
	s.EdgeOpened(id, tB)
	if err := s.Flush(tB.Add(15 * time.Second)); err != nil {
		t.Fatal(err)
	}

	snapB, err := s.SnapshotAt(tB.Add(20*time.Second), 2*time.Minute, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range snapB.Nodes {
		if n.ID == "proc:/usr/sbin/nginx" && len(n.ListenPorts) != 0 {
			t.Fatalf("stale listen ports shown at B: %+v", n)
		}
	}

	// And era A still shows the port it had then.
	snapA, err := s.SnapshotAt(t0.Add(30*time.Second), 2*time.Minute, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range snapA.Nodes {
		if n.ID == "proc:/usr/sbin/nginx" && (len(n.ListenPorts) != 1 || n.ListenPorts[0] != 8080) {
			t.Fatalf("era A ports wrong: %+v", n)
		}
	}
}

// While a flush transaction is in flight, drained lifecycle events and
// metric buckets are staged, not gone: a concurrent reader must still
// see them. (Without staging, every flush opened an up-to-10s gap in
// /api/lifecycle, /api/metrics and the timeline markers.)
func TestStagedFlushKeepsEventsAndMetricsVisible(t *testing.T) {
	g := seedGraph()
	s := openTest(t, g)
	at := t0.Add(5 * time.Second)
	s.NodeEvent("proc:/usr/sbin/nginx", "oom", 200, "pid 200 chosen", at)
	s.NodeSample("proc:/usr/sbin/nginx", graphNodeMetrics(64<<20), at)

	// Reproduce Flush's drain exactly as a reader would see it mid-tx.
	s.mu.Lock()
	s.flushingEvents = s.pendingEvents
	s.pendingEvents = nil
	s.pendingEventCounts = make(map[string]int)
	s.flushingMetrics = s.metrics
	s.metrics = make(map[metricKey]*metricAcc)
	s.mu.Unlock()

	events, err := s.LifecycleRange(t0.Add(-time.Minute), at.Add(time.Minute), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Kind != "oom" {
		t.Fatalf("staged event invisible to LifecycleRange: %+v", events)
	}
	points, err := s.MetricsRange("proc:/usr/sbin/nginx", t0.Add(-time.Minute), at.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(points) != 1 || points[0].Metrics.RSSBytes != 64<<20 {
		t.Fatalf("staged metrics invisible to MetricsRange: %+v", points)
	}
	tl, err := s.Timeline(t0.Add(-time.Minute), at.Add(time.Minute), 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var ooms uint64
	for _, b := range tl {
		ooms += b.Ooms
	}
	if ooms != 1 {
		t.Fatalf("staged event invisible to timeline markers: %+v", tl)
	}
}

func graphNodeMetrics(rss uint64) graph.NodeMetrics {
	return graph.NodeMetrics{WindowSecs: 10, CPUMillis: 100, RSSBytes: rss, Procs: 1}
}

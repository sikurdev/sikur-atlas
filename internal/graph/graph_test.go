package graph

import (
	"testing"
	"time"
)

var (
	t0 = time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	t1 = t0.Add(time.Second)
	t2 = t0.Add(2 * time.Second)
)

func spec(id string, kind NodeKind, pid uint32) NodeSpec {
	return NodeSpec{ID: id, Kind: kind, Label: id, PID: pid}
}

func TestObserveConnectionCreatesNodesAndEdge(t *testing.T) {
	s := NewStore()
	edgeID := s.ObserveConnection(spec("proc:/bin/curl", NodeProcess, 100), spec("proc:/bin/nginx", NodeProcess, 200), 8080, t0)

	snap := s.Snapshot()
	if len(snap.Nodes) != 2 {
		t.Fatalf("nodes = %d, want 2", len(snap.Nodes))
	}
	if len(snap.Edges) != 1 {
		t.Fatalf("edges = %d, want 1", len(snap.Edges))
	}
	e := snap.Edges[0]
	if e.ID != edgeID || e.Src != "proc:/bin/curl" || e.Dst != "proc:/bin/nginx" || e.DstPort != 8080 {
		t.Fatalf("unexpected edge %+v", e)
	}
	if e.Connections != 1 || e.ActiveConns != 1 {
		t.Fatalf("counts = %d/%d, want 1/1", e.Connections, e.ActiveConns)
	}
	if !e.FirstSeen.Equal(t0) || !e.LastSeen.Equal(t0) {
		t.Fatalf("timestamps %v %v, want %v", e.FirstSeen, e.LastSeen, t0)
	}
}

func TestRepeatConnectionsAggregate(t *testing.T) {
	s := NewStore()
	a, b := spec("a", NodeProcess, 1), spec("b", NodeProcess, 2)
	id := s.ObserveConnection(a, b, 80, t0)
	if got := s.ObserveConnection(a, b, 80, t1); got != id {
		t.Fatalf("edge id changed: %q vs %q", got, id)
	}

	snap := s.Snapshot()
	if len(snap.Edges) != 1 {
		t.Fatalf("edges = %d, want 1", len(snap.Edges))
	}
	e := snap.Edges[0]
	if e.Connections != 2 || e.ActiveConns != 2 {
		t.Fatalf("counts = %d/%d, want 2/2", e.Connections, e.ActiveConns)
	}
	if !e.FirstSeen.Equal(t0) || !e.LastSeen.Equal(t1) {
		t.Fatalf("first/last %v/%v", e.FirstSeen, e.LastSeen)
	}
}

func TestConnectionClosedFoldsBytesOnce(t *testing.T) {
	s := NewStore()
	id := s.ObserveConnection(spec("a", NodeProcess, 1), spec("b", NodeProcess, 2), 80, t0)

	s.ConnectionClosed(id, 500, 1000, t1, true)
	s.ConnectionClosed(id, 500, 1000, t2, false) // twin socket close: no double count

	e := s.Snapshot().Edges[0]
	if e.BytesSent != 500 || e.BytesRecv != 1000 {
		t.Fatalf("bytes = %d/%d, want 500/1000", e.BytesSent, e.BytesRecv)
	}
	if e.ActiveConns != 0 {
		t.Fatalf("active = %d, want 0 (not negative)", e.ActiveConns)
	}
	if !e.LastSeen.Equal(t2) {
		t.Fatalf("lastSeen = %v, want %v", e.LastSeen, t2)
	}
}

func TestUpsertMergesPIDsAndAddrs(t *testing.T) {
	s := NewStore()
	a1 := NodeSpec{ID: "proc:/bin/nginx", Kind: NodeProcess, Label: "nginx", PID: 10, Addr: "10.0.0.1"}
	a2 := NodeSpec{ID: "proc:/bin/nginx", Kind: NodeProcess, Label: "nginx", PID: 11, Addr: "10.0.0.2"}
	s.ObserveConnection(a1, spec("x", NodeExternal, 0), 443, t0)
	s.ObserveConnection(a2, spec("x", NodeExternal, 0), 443, t1)

	snap := s.Snapshot()
	var nginx *Node
	for i := range snap.Nodes {
		if snap.Nodes[i].ID == "proc:/bin/nginx" {
			nginx = &snap.Nodes[i]
		}
	}
	if nginx == nil {
		t.Fatal("nginx node missing")
	}
	if len(nginx.PIDs) != 2 || nginx.PIDs[0] != 10 || nginx.PIDs[1] != 11 {
		t.Fatalf("pids = %v", nginx.PIDs)
	}
	if len(nginx.Addrs) != 2 {
		t.Fatalf("addrs = %v", nginx.Addrs)
	}
}

func TestSyncListeners(t *testing.T) {
	s := NewStore()
	sp := spec("proc:/bin/nginx", NodeProcess, 10)

	s.SyncListeners([]ListenerSet{{Spec: sp, Ports: []uint16{443, 80, 80}}}, t0)
	n := s.Snapshot().Nodes[0]
	if len(n.ListenPorts) != 2 || n.ListenPorts[0] != 80 || n.ListenPorts[1] != 443 {
		t.Fatalf("listenPorts = %v (want sorted, deduped)", n.ListenPorts)
	}

	// An identical scan must not bump the version.
	v := s.Version()
	s.SyncListeners([]ListenerSet{{Spec: sp, Ports: []uint16{80, 443}}}, t1)
	if s.Version() != v {
		t.Fatal("no-op scan bumped version")
	}

	// A scan without the node clears its ports: stopped services stop
	// showing stale listeners.
	s.SyncListeners(nil, t1)
	n = s.Snapshot().Nodes[0]
	if len(n.ListenPorts) != 0 {
		t.Fatalf("stale ports survived: %v", n.ListenPorts)
	}

	// A scan can create a node that has produced no traffic yet.
	other := spec("proc:/bin/postgres", NodeProcess, 20)
	s.SyncListeners([]ListenerSet{{Spec: other, Ports: []uint16{5432}}}, t2)
	snap := s.Snapshot()
	if len(snap.Nodes) != 2 {
		t.Fatalf("nodes = %d, want 2", len(snap.Nodes))
	}
}

func TestSetContainerMetaUpdatesLabel(t *testing.T) {
	s := NewStore()
	cs := NodeSpec{ID: "container:abc123def456", Kind: NodeContainer, Label: "abc123def456", ContainerID: "abc123def456" + "0000"}
	s.ObserveConnection(cs, spec("x", NodeExternal, 0), 80, t0)

	s.SetContainerMeta("container:abc123def456", "demo-gateway", "nginx:alpine")
	n := s.Snapshot().Nodes[0]
	if n.Label != "demo-gateway" || n.ContainerName != "demo-gateway" || n.Image != "nginx:alpine" {
		t.Fatalf("meta not applied: %+v", n)
	}

	// Unknown node: must not panic or create phantom nodes.
	s.SetContainerMeta("container:missing", "x", "y")
	if len(s.Snapshot().Nodes) != 2 {
		t.Fatal("phantom node created")
	}
}

// Async enrichment can resolve a container before its first connection
// creates the node (its exec event enqueues the lookup at container
// start). The metadata must survive that race and land when the node
// appears — this exact ordering made every demo container keep its
// short-id label on a real kernel.
func TestContainerMetaBeforeNodeExists(t *testing.T) {
	s := NewStore()
	s.SetContainerMeta("container:abc123def456", "demo-gateway", "nginx:alpine")
	s.SetComposeIdentity("container:abc123def456", "demo", "gateway")

	cs := NodeSpec{ID: "container:abc123def456", Kind: NodeContainer, Label: "abc123def456", ContainerID: "abc123def456" + "0000"}
	s.ObserveConnection(cs, spec("x", NodeExternal, 0), 80, t0)

	var n Node
	for _, cand := range s.Snapshot().Nodes {
		if cand.ID == "container:abc123def456" {
			n = cand
		}
	}
	if n.Label != "demo-gateway" || n.ContainerName != "demo-gateway" || n.Image != "nginx:alpine" {
		t.Fatalf("stashed meta not applied on creation: %+v", n)
	}
	if n.ComposeProject != "demo" || n.ComposeService != "gateway" {
		t.Fatalf("stashed compose identity not applied: %+v", n)
	}

	// The stash is consumed: a second node with the same id cannot
	// exist, and re-creating after removal must not resurrect old meta.
	s.mu.Lock()
	if len(s.pending) != 0 {
		s.mu.Unlock()
		t.Fatal("pending stash not cleared after apply")
	}
	s.mu.Unlock()
}

// UpsertNode must notify on mutation of an existing node (new pid,
// address, exe), not only on creation — a unix-only listener that
// restarts with a new pid would otherwise stay stale for subscribers.
func TestUpsertNodeBumpsOnMutation(t *testing.T) {
	s := NewStore()
	base := NodeSpec{ID: "proc:/bin/reports", Kind: NodeProcess, Label: "reports", PID: 100}
	s.UpsertNode(base, t0)
	v := s.Version()

	s.UpsertNode(base, t1) // nothing new: quiet scans must not churn
	if s.Version() != v {
		t.Fatalf("identical upsert bumped version")
	}

	restarted := base
	restarted.PID = 101
	s.UpsertNode(restarted, t1)
	if s.Version() == v {
		t.Fatal("new pid did not notify subscribers")
	}
}

func TestSubscribeCoalesces(t *testing.T) {
	s := NewStore()
	ch, cancel := s.Subscribe()
	defer cancel()

	for i := 0; i < 5; i++ {
		s.ObserveConnection(spec("a", NodeProcess, 1), spec("b", NodeProcess, 2), 80, t0)
	}
	select {
	case <-ch:
	default:
		t.Fatal("expected a pending notification")
	}
	select {
	case <-ch:
		t.Fatal("notifications were not coalesced")
	default:
	}
}

func TestSnapshotDeterministicOrder(t *testing.T) {
	s := NewStore()
	s.ObserveConnection(spec("b", NodeProcess, 2), spec("a", NodeProcess, 1), 80, t0)
	s.ObserveConnection(spec("c", NodeProcess, 3), spec("a", NodeProcess, 1), 80, t0)

	snap := s.Snapshot()
	if snap.Nodes[0].ID != "a" || snap.Nodes[1].ID != "b" || snap.Nodes[2].ID != "c" {
		t.Fatalf("nodes not sorted: %v", []string{snap.Nodes[0].ID, snap.Nodes[1].ID, snap.Nodes[2].ID})
	}
	if snap.Edges[0].ID >= snap.Edges[1].ID {
		t.Fatal("edges not sorted")
	}
}

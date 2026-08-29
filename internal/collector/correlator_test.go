package collector

import (
	"net/netip"
	"testing"
	"time"

	"github.com/sikurdev/sikur-atlas/internal/graph"
	"github.com/sikurdev/sikur-atlas/internal/model"
)

type fakeResolver map[uint32]model.ProcessInfo

func (f fakeResolver) Resolve(pid uint32, comm string) model.ProcessInfo {
	if info, ok := f[pid]; ok {
		return info
	}
	return model.ProcessInfo{PID: pid, Comm: comm}
}

var base = time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)

func ap(addr string, port uint16) netip.AddrPort {
	return netip.AddrPortFrom(netip.MustParseAddr(addr), port)
}

func ev(t model.EventType, sock uint64, pid uint32, comm string, src, dst netip.AddrPort, offsetMs int) model.ConnEvent {
	return model.ConnEvent{
		Time:   base.Add(time.Duration(offsetMs) * time.Millisecond),
		Type:   t,
		PID:    pid,
		Comm:   comm,
		SockID: sock,
		Src:    src,
		Dst:    dst,
	}
}

func newTestCorrelator(res ProcessResolver) (*Correlator, *graph.Store) {
	store := graph.NewStore()
	c := New(store, res, WithGracePeriod(time.Second))
	return c, store
}

func edgeByID(t *testing.T, s *graph.Store, id string) graph.Edge {
	t.Helper()
	for _, e := range s.Snapshot().Edges {
		if e.ID == id {
			return e
		}
	}
	t.Fatalf("edge %q not found; have %+v", id, s.Snapshot().Edges)
	return graph.Edge{}
}

// The canonical loopback flow: both socket halves observed, merged into a
// single process→process edge.
func TestLoopbackConnectionMergesToOneEdge(t *testing.T) {
	res := fakeResolver{
		100: {PID: 100, Comm: "curl", Exe: "/usr/bin/curl"},
		200: {PID: 200, Comm: "nginx", Exe: "/usr/sbin/nginx"},
	}
	c, store := newTestCorrelator(res)

	cli := ap("127.0.0.1", 41000)
	srv := ap("127.0.0.1", 8080)

	c.HandleEvent(ev(model.EventOpen, 1, 100, "curl", netip.AddrPort{}, srv, 0))
	c.HandleEvent(ev(model.EventEstablished, 1, 0, "", cli, srv, 1))
	c.HandleEvent(ev(model.EventEstablished, 2, 0, "", srv, cli, 2))
	c.HandleEvent(ev(model.EventAccept, 2, 200, "nginx", srv, cli, 3))

	snap := store.Snapshot()
	if len(snap.Edges) != 1 {
		t.Fatalf("edges = %d, want 1 (halves must merge); %+v", len(snap.Edges), snap.Edges)
	}
	e := snap.Edges[0]
	if e.Src != "proc:/usr/bin/curl" || e.Dst != "proc:/usr/sbin/nginx" || e.DstPort != 8080 {
		t.Fatalf("unexpected edge %+v", e)
	}
	if e.ActiveConns != 1 || e.Connections != 1 {
		t.Fatalf("counts %d/%d, want 1/1", e.Connections, e.ActiveConns)
	}

	// Close both halves; bytes counted once, from the client's view.
	closeEv := ev(model.EventClose, 1, 0, "", cli, srv, 500)
	closeEv.BytesSent, closeEv.BytesRecv = 500, 1000
	c.HandleEvent(closeEv)
	closeEv2 := ev(model.EventClose, 2, 0, "", srv, cli, 501)
	closeEv2.BytesSent, closeEv2.BytesRecv = 1000, 500
	c.HandleEvent(closeEv2)

	e = edgeByID(t, store, e.ID)
	if e.ActiveConns != 0 {
		t.Fatalf("active = %d, want 0", e.ActiveConns)
	}
	if e.BytesSent != 500 || e.BytesRecv != 1000 {
		t.Fatalf("bytes = %d/%d, want 500/1000 (counted once, client view)", e.BytesSent, e.BytesRecv)
	}

	st := c.Stats()
	if st.LiveSockets != 0 || st.LiveRecords != 0 {
		t.Fatalf("state leaked: %+v", st)
	}
}

// Outbound connection to a peer that is not on this host: after the grace
// period the peer becomes an external node.
func TestOutboundToExternalPeer(t *testing.T) {
	res := fakeResolver{100: {PID: 100, Comm: "curl", Exe: "/usr/bin/curl"}}
	c, store := newTestCorrelator(res)

	cli := ap("10.0.0.5", 52000)
	srv := ap("93.184.216.34", 443)

	c.HandleEvent(ev(model.EventOpen, 1, 100, "curl", netip.AddrPort{}, srv, 0))
	c.HandleEvent(ev(model.EventEstablished, 1, 0, "", cli, srv, 1))

	if n := len(store.Snapshot().Edges); n != 0 {
		t.Fatalf("edge materialized before grace period: %d", n)
	}
	c.Tick(base.Add(2 * time.Second))

	snap := store.Snapshot()
	if len(snap.Edges) != 1 {
		t.Fatalf("edges = %d, want 1", len(snap.Edges))
	}
	e := snap.Edges[0]
	if e.Src != "proc:/usr/bin/curl" || e.Dst != "ext:93.184.216.34" || e.DstPort != 443 {
		t.Fatalf("unexpected edge %+v", e)
	}

	closeEv := ev(model.EventClose, 1, 0, "", cli, srv, 3000)
	closeEv.BytesSent, closeEv.BytesRecv = 111, 2222
	c.HandleEvent(closeEv)
	e = edgeByID(t, store, e.ID)
	if e.BytesSent != 111 || e.BytesRecv != 2222 || e.ActiveConns != 0 {
		t.Fatalf("close not folded: %+v", e)
	}
}

// Inbound connection from off-host: server side resolves, client becomes
// external.
func TestInboundFromExternalPeer(t *testing.T) {
	res := fakeResolver{200: {PID: 200, Comm: "nginx", Exe: "/usr/sbin/nginx"}}
	c, store := newTestCorrelator(res)

	local := ap("10.0.0.5", 8080)
	peer := ap("198.51.100.7", 55555)

	c.HandleEvent(ev(model.EventEstablished, 9, 0, "", local, peer, 0))
	c.HandleEvent(ev(model.EventAccept, 9, 200, "nginx", local, peer, 1))

	// Client half can never appear (it is off-host); grace must expire.
	c.Tick(base.Add(2 * time.Second))

	snap := store.Snapshot()
	if len(snap.Edges) != 1 {
		t.Fatalf("edges = %d, want 1", len(snap.Edges))
	}
	e := snap.Edges[0]
	if e.Src != "ext:198.51.100.7" || e.Dst != "proc:/usr/sbin/nginx" || e.DstPort != 8080 {
		t.Fatalf("unexpected edge %+v", e)
	}
}

// A connect that never completes becomes a failure on the edge towards
// its target — never a connection.
func TestFailedConnectRecordsFailure(t *testing.T) {
	res := fakeResolver{100: {PID: 100, Comm: "curl", Exe: "/usr/bin/curl"}}
	c, store := newTestCorrelator(res)

	c.HandleEvent(ev(model.EventOpen, 1, 100, "curl", netip.AddrPort{}, ap("10.9.9.9", 81), 0))
	// SYN retransmit and an RST while still connecting.
	c.HandleEvent(ev(model.EventRetrans, 1, 0, "", netip.AddrPort{}, netip.AddrPort{}, 50))
	c.HandleEvent(ev(model.EventReset, 1, 0, "", netip.AddrPort{}, netip.AddrPort{}, 60))
	c.HandleEvent(ev(model.EventClose, 1, 0, "", netip.AddrPort{}, ap("10.9.9.9", 81), 100))

	snap := store.Snapshot()
	if len(snap.Edges) != 1 {
		t.Fatalf("edges = %d, want 1 failure edge", len(snap.Edges))
	}
	e := snap.Edges[0]
	if e.Src != "proc:/usr/bin/curl" || e.Dst != "ext:10.9.9.9" || e.DstPort != 81 {
		t.Fatalf("unexpected edge %+v", e)
	}
	if e.Failures != 1 || e.Connections != 0 || e.ActiveConns != 0 {
		t.Fatalf("failure accounting wrong: %+v", e)
	}
	if e.Retransmits != 1 || e.Resets != 1 {
		t.Fatalf("pre-establishment health lost: %+v", e)
	}
	st := c.Stats()
	if st.LiveSockets != 0 || st.LiveRecords != 0 {
		t.Fatalf("state leaked: %+v", st)
	}
	if st.FailedConns != 1 {
		t.Fatalf("failedConns = %d, want 1", st.FailedConns)
	}
}

// A failed connect towards a known container address names the target
// service instead of an external node.
func TestFailedConnectToKnownContainer(t *testing.T) {
	cid := "feedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface"
	res := fakeResolver{
		100: {PID: 100, Comm: "curl", Exe: "/usr/bin/curl"},
		300: {PID: 300, Comm: "redis-server", Exe: "/usr/bin/redis-server", ContainerID: cid},
	}
	c, store := newTestCorrelator(res)

	// A successful connection first teaches Atlas the container's address.
	cacheAddr := ap("172.17.0.9", 6379)
	cli := ap("172.17.0.1", 41000)
	c.HandleEvent(ev(model.EventOpen, 1, 100, "curl", netip.AddrPort{}, cacheAddr, 0))
	c.HandleEvent(ev(model.EventEstablished, 1, 0, "", cli, cacheAddr, 1))
	c.HandleEvent(ev(model.EventAccept, 2, 300, "redis-server", cacheAddr, cli, 2))

	// Now a refused connect to a different port on the same container.
	c.HandleEvent(ev(model.EventOpen, 5, 100, "curl", netip.AddrPort{}, ap("172.17.0.9", 6380), 100))
	c.HandleEvent(ev(model.EventClose, 5, 0, "", netip.AddrPort{}, ap("172.17.0.9", 6380), 150))

	snap := store.Snapshot()
	var failEdge *graph.Edge
	for i := range snap.Edges {
		if snap.Edges[i].DstPort == 6380 {
			failEdge = &snap.Edges[i]
		}
	}
	if failEdge == nil {
		t.Fatalf("failure edge missing: %+v", snap.Edges)
	}
	if failEdge.Dst != "container:feedfacefeed" {
		t.Fatalf("failure not attributed to container: %+v", failEdge)
	}
	if failEdge.Failures != 1 {
		t.Fatalf("failures = %d", failEdge.Failures)
	}
}

// Under load the client can close before the server's accept() returns.
// The close must wait for the accept so the server is not misattributed
// as external, and the active counter must not go phantom-positive.
func TestClientCloseBeforeAccept(t *testing.T) {
	res := fakeResolver{
		100: {PID: 100, Comm: "curl", Exe: "/usr/bin/curl"},
		200: {PID: 200, Comm: "nginx", Exe: "/usr/sbin/nginx"},
	}
	c, store := newTestCorrelator(res)

	cli := ap("127.0.0.1", 41000)
	srv := ap("127.0.0.1", 8080)

	c.HandleEvent(ev(model.EventOpen, 1, 100, "curl", netip.AddrPort{}, srv, 0))
	c.HandleEvent(ev(model.EventEstablished, 1, 0, "", cli, srv, 1))
	c.HandleEvent(ev(model.EventEstablished, 2, 0, "", srv, cli, 2))

	closeEv := ev(model.EventClose, 1, 0, "", cli, srv, 10)
	closeEv.BytesSent, closeEv.BytesRecv = 300, 900
	c.HandleEvent(closeEv)

	if n := len(store.Snapshot().Edges); n != 0 {
		t.Fatalf("edge materialized from a stale half: %d", n)
	}

	c.HandleEvent(ev(model.EventAccept, 2, 200, "nginx", srv, cli, 20))

	snap := store.Snapshot()
	if len(snap.Edges) != 1 {
		t.Fatalf("edges = %d, want 1", len(snap.Edges))
	}
	e := snap.Edges[0]
	if e.Dst != "proc:/usr/sbin/nginx" {
		t.Fatalf("server misattributed: %+v", e)
	}
	if e.ActiveConns != 0 {
		t.Fatalf("active = %d, want 0 (stashed close must apply on materialize)", e.ActiveConns)
	}
	if e.BytesSent != 300 || e.BytesRecv != 900 {
		t.Fatalf("bytes = %d/%d, want 300/900", e.BytesSent, e.BytesRecv)
	}
}

// Containerized processes become container nodes and fire the
// enrichment hook (dedup is the enricher's job).
func TestContainerAttribution(t *testing.T) {
	cid := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	res := fakeResolver{
		300: {PID: 300, Comm: "python3", Exe: "/usr/local/bin/python3.12", ContainerID: cid},
		100: {PID: 100, Comm: "curl", Exe: "/usr/bin/curl"},
	}
	var hooked []string
	store := graph.NewStore()
	c := New(store, res, WithGracePeriod(time.Second), WithContainerHook(func(id string) {
		hooked = append(hooked, id)
	}))

	srv := ap("172.17.0.2", 8000)
	for i := 0; i < 2; i++ {
		cli := ap("172.17.0.1", uint16(41000+i))
		sockA, sockB := uint64(10+i*2), uint64(11+i*2)
		c.HandleEvent(ev(model.EventOpen, sockA, 100, "curl", netip.AddrPort{}, srv, i*100))
		c.HandleEvent(ev(model.EventEstablished, sockA, 0, "", cli, srv, i*100+1))
		c.HandleEvent(ev(model.EventAccept, sockB, 300, "python3", srv, cli, i*100+2))
	}

	snap := store.Snapshot()
	var node *graph.Node
	for i := range snap.Nodes {
		if snap.Nodes[i].Kind == graph.NodeContainer {
			node = &snap.Nodes[i]
		}
	}
	if node == nil {
		t.Fatalf("no container node: %+v", snap.Nodes)
	}
	if node.ID != "container:0123456789ab" || node.ContainerID != cid {
		t.Fatalf("unexpected container node %+v", node)
	}
	if len(hooked) == 0 {
		t.Fatal("container hook never fired")
	}
	for _, h := range hooked {
		if h != cid {
			t.Fatalf("hook fired with wrong id %q", h)
		}
	}

	e := snap.Edges[0]
	if e.Connections != 2 {
		t.Fatalf("connections = %d, want 2", e.Connections)
	}
}

// A socket that reaches ESTABLISHED with no open and no accept (the app
// never called accept before grace expiry) is attributed as server via
// the orientation hint.
func TestOrientationHintForUnaccepted(t *testing.T) {
	c, store := newTestCorrelator(fakeResolver{})

	local := ap("10.0.0.5", 8080)
	peer := ap("198.51.100.7", 55555)
	c.HandleEvent(ev(model.EventEstablished, 9, 0, "", local, peer, 0))
	c.Tick(base.Add(2 * time.Second))

	snap := store.Snapshot()
	if len(snap.Edges) != 1 {
		t.Fatalf("edges = %d, want 1", len(snap.Edges))
	}
	e := snap.Edges[0]
	if e.DstPort != 8080 {
		t.Fatalf("hint ignored, edge %+v", e)
	}
	if e.Src != "ext:198.51.100.7" {
		t.Fatalf("client side wrong: %+v", e)
	}
}

func TestSyncListeners(t *testing.T) {
	res := fakeResolver{
		200: {PID: 200, Comm: "nginx", Exe: "/usr/sbin/nginx"},
		201: {PID: 201, Comm: "nginx", Exe: "/usr/sbin/nginx"},
	}
	c, store := newTestCorrelator(res)

	// Two worker pids of the same executable merge into one node.
	c.SyncListeners([]Listener{
		{PID: 200, Comm: "nginx", Addr: netip.MustParseAddr("0.0.0.0"), Port: 8080},
		{PID: 201, Comm: "nginx", Addr: netip.MustParseAddr("0.0.0.0"), Port: 8443},
	}, base)

	snap := store.Snapshot()
	if len(snap.Nodes) != 1 {
		t.Fatalf("nodes = %d, want 1", len(snap.Nodes))
	}
	n := snap.Nodes[0]
	if n.ID != "proc:/usr/sbin/nginx" || len(n.ListenPorts) != 2 {
		t.Fatalf("unexpected node %+v", n)
	}

	// The service stops: next scan clears its ports.
	c.SyncListeners(nil, base.Add(30*time.Second))
	if got := store.Snapshot().Nodes[0].ListenPorts; len(got) != 0 {
		t.Fatalf("ports survived stop: %v", got)
	}
}

// Stale tracking state from lost close events is swept.
func TestIdleSweep(t *testing.T) {
	store := graph.NewStore()
	c := New(store, fakeResolver{}, WithIdleTTL(time.Minute))

	c.HandleEvent(ev(model.EventOpen, 1, 100, "curl", netip.AddrPort{}, ap("10.9.9.9", 81), 0))
	c.Tick(base.Add(2 * time.Minute))

	st := c.Stats()
	if st.LiveSockets != 0 {
		t.Fatalf("stale socket survived sweep: %+v", st)
	}
}

// A connection outliving the idle TTL produces no events while alive;
// aging it out must release the edge's active count instead of leaving
// it stuck forever, and its eventual close must be a no-op.
func TestIdleSweepReleasesActiveCount(t *testing.T) {
	res := fakeResolver{100: {PID: 100, Comm: "curl", Exe: "/usr/bin/curl"}}
	store := graph.NewStore()
	c := New(store, res, WithGracePeriod(time.Second), WithIdleTTL(time.Minute))

	cli := ap("10.0.0.5", 52000)
	srv := ap("93.184.216.34", 443)
	c.HandleEvent(ev(model.EventOpen, 1, 100, "curl", netip.AddrPort{}, srv, 0))
	c.HandleEvent(ev(model.EventEstablished, 1, 0, "", cli, srv, 1))
	c.Tick(base.Add(2 * time.Second)) // materializes

	if e := store.Snapshot().Edges[0]; e.ActiveConns != 1 {
		t.Fatalf("active = %d, want 1", e.ActiveConns)
	}

	c.Tick(base.Add(2 * time.Minute)) // TTL expiry

	e := store.Snapshot().Edges[0]
	if e.ActiveConns != 0 {
		t.Fatalf("active = %d after sweep, want 0", e.ActiveConns)
	}
	if c.Stats().LiveRecords != 0 {
		t.Fatalf("record survived sweep: %+v", c.Stats())
	}

	// The real close arrives much later; it must not corrupt anything.
	closeEv := ev(model.EventClose, 1, 0, "", cli, srv, 180_000)
	closeEv.BytesSent = 999
	c.HandleEvent(closeEv)
	e = store.Snapshot().Edges[0]
	if e.ActiveConns != 0 || e.BytesSent != 0 {
		t.Fatalf("late close corrupted edge: %+v", e)
	}
}

// The kernel can reuse a socket address after a close event was lost to
// ring buffer overflow. The new connection must not inherit the old
// tuple key: its bytes belong to its own edge.
func TestSockAddressReuseAfterLostClose(t *testing.T) {
	res := fakeResolver{100: {PID: 100, Comm: "curl", Exe: "/usr/bin/curl"}}
	c, store := newTestCorrelator(res)

	oldSrv := ap("10.1.1.1", 443)
	c.HandleEvent(ev(model.EventOpen, 1, 100, "curl", netip.AddrPort{}, oldSrv, 0))
	c.HandleEvent(ev(model.EventEstablished, 1, 0, "", ap("10.0.0.5", 52000), oldSrv, 1))
	c.Tick(base.Add(2 * time.Second))
	oldEdge := store.Snapshot().Edges[0]

	// CLOSE for sock 1 is lost; the kernel reuses the address for a new
	// connection to a different server.
	newSrv := ap("10.2.2.2", 9090)
	newCli := ap("10.0.0.5", 52001)
	c.HandleEvent(ev(model.EventOpen, 1, 100, "curl", netip.AddrPort{}, newSrv, 5000))
	c.HandleEvent(ev(model.EventEstablished, 1, 0, "", newCli, newSrv, 5001))

	closeEv := ev(model.EventClose, 1, 0, "", newCli, newSrv, 6000)
	closeEv.BytesSent, closeEv.BytesRecv = 700, 70
	c.HandleEvent(closeEv)
	// The close is stashed until the grace deadline resolves endpoints.
	c.Tick(base.Add(10 * time.Second))

	snap := store.Snapshot()
	for _, e := range snap.Edges {
		switch e.ID {
		case oldEdge.ID:
			if e.BytesSent != 0 || e.BytesRecv != 0 {
				t.Fatalf("bytes misattributed to stale edge: %+v", e)
			}
		default:
			if e.DstPort == 9090 && (e.BytesSent != 700 || e.BytesRecv != 70) {
				t.Fatalf("new edge bytes wrong: %+v", e)
			}
		}
	}
	var found bool
	for _, e := range snap.Edges {
		if e.DstPort == 9090 {
			found = true
		}
		if e.ID == oldEdge.ID && e.ActiveConns != 0 {
			t.Fatalf("stale edge's active count not released: %+v", e)
		}
	}
	if !found {
		t.Fatalf("new connection's edge missing: %+v", snap.Edges)
	}
	if c.Stats().LiveRecords != 0 || c.Stats().LiveSockets != 0 {
		t.Fatalf("state leaked: %+v", c.Stats())
	}
}

// A close carrying byte counters proves the handshake happened even if
// the establish event was lost — it must not count as a failed connect.
func TestDroppedEstablishIsNotAFailure(t *testing.T) {
	res := fakeResolver{100: {PID: 100, Comm: "curl", Exe: "/usr/bin/curl"}}
	c, store := newTestCorrelator(res)

	c.HandleEvent(ev(model.EventOpen, 1, 100, "curl", netip.AddrPort{}, ap("10.0.0.9", 443), 0))
	closeEv := ev(model.EventClose, 1, 0, "", ap("10.0.0.5", 50000), ap("10.0.0.9", 443), 5000)
	closeEv.BytesSent, closeEv.BytesRecv = 900, 4000
	closeEv.SRTTMicros = 1200
	c.HandleEvent(closeEv)

	snap := store.Snapshot()
	for _, e := range snap.Edges {
		if e.Failures > 0 {
			t.Fatalf("established connection reported as failure: %+v", e)
		}
	}
	if c.Stats().FailedConns != 0 {
		t.Fatalf("failedConns = %d, want 0", c.Stats().FailedConns)
	}
}

// The server's establish event is lost AND accept trails the client's
// close: the stash must survive until accept identifies the server, and
// the connection must count exactly once.
func TestAcceptAfterCloseWithLostServerEstablish(t *testing.T) {
	res := fakeResolver{
		100: {PID: 100, Comm: "curl", Exe: "/usr/bin/curl"},
		200: {PID: 200, Comm: "nginx", Exe: "/usr/sbin/nginx"},
	}
	c, store := newTestCorrelator(res)

	cli := ap("127.0.0.1", 41000)
	srv := ap("127.0.0.1", 8080)
	c.HandleEvent(ev(model.EventOpen, 1, 100, "curl", netip.AddrPort{}, srv, 0))
	c.HandleEvent(ev(model.EventEstablished, 1, 0, "", cli, srv, 1))
	// Server-side EventEstablished for sock 2 lost to ring overflow.
	closeEv := ev(model.EventClose, 1, 0, "", cli, srv, 10)
	closeEv.BytesSent, closeEv.BytesRecv = 300, 900
	c.HandleEvent(closeEv)

	if n := len(store.Snapshot().Edges); n != 0 {
		t.Fatalf("edge materialized before the server identified itself: %d", n)
	}

	c.HandleEvent(ev(model.EventAccept, 2, 200, "nginx", srv, cli, 20))
	snap := store.Snapshot()
	if len(snap.Edges) != 1 {
		t.Fatalf("edges = %d, want exactly 1 (no double count)", len(snap.Edges))
	}
	e := snap.Edges[0]
	if e.Dst != "proc:/usr/sbin/nginx" || e.Connections != 1 || e.ActiveConns != 0 {
		t.Fatalf("edge = %+v", e)
	}
	if e.BytesSent != 300 || e.BytesRecv != 900 {
		t.Fatalf("bytes = %d/%d", e.BytesSent, e.BytesRecv)
	}

	// The server socket's own close cleans up without another count.
	c.HandleEvent(ev(model.EventClose, 2, 0, "", srv, cli, 30))
	c.Tick(base.Add(10 * time.Second))
	snap = store.Snapshot()
	if snap.Edges[0].Connections != 1 {
		t.Fatalf("double counted: %+v", snap.Edges[0])
	}
	if st := c.Stats(); st.LiveRecords != 0 || st.LiveSockets != 0 {
		t.Fatalf("state leaked: %+v", st)
	}
}

// fakeRecorder captures Recorder calls for pairing verification.
type fakeRecorder struct {
	opened, closed, expired int
	failures                int
	retrans, resets         uint64
	rtts                    []uint32
}

func (r *fakeRecorder) EdgeOpened(string, time.Time) { r.opened++ }
func (r *fakeRecorder) EdgeClosed(_ string, _, _ uint64, rtt uint32, _ time.Time) {
	r.closed++
	if rtt > 0 {
		r.rtts = append(r.rtts, rtt)
	}
}
func (r *fakeRecorder) EdgeExpired(string, time.Time)               { r.expired++ }
func (r *fakeRecorder) EdgeFailure(string, time.Time)               { r.failures++ }
func (r *fakeRecorder) EdgeResets(_ string, n uint64, _ time.Time)  { r.resets += n }
func (r *fakeRecorder) EdgeRetrans(_ string, n uint64, _ time.Time) { r.retrans += n }
func (r *fakeRecorder) EdgeRTT(_ string, rtt uint32, _ time.Time) {
	if rtt > 0 {
		r.rtts = append(r.rtts, rtt)
	}
}

// Every EdgeOpened must be balanced by exactly one EdgeClosed or
// EdgeExpired, across normal closes, lost closes (idle sweep) and
// socket-address reuse — otherwise history's active counts drift.
func TestRecorderPairing(t *testing.T) {
	res := fakeResolver{
		100: {PID: 100, Comm: "curl", Exe: "/usr/bin/curl"},
		200: {PID: 200, Comm: "nginx", Exe: "/usr/sbin/nginx"},
	}
	rec := &fakeRecorder{}
	store := graph.NewStore()
	c := New(store, res,
		WithGracePeriod(time.Second),
		WithIdleTTL(time.Minute),
		WithRecorder(rec))

	cli := ap("127.0.0.1", 41000)
	srv := ap("127.0.0.1", 8080)

	// 1: clean loopback connection, both halves close.
	c.HandleEvent(ev(model.EventOpen, 1, 100, "curl", netip.AddrPort{}, srv, 0))
	c.HandleEvent(ev(model.EventEstablished, 1, 0, "", cli, srv, 1))
	c.HandleEvent(ev(model.EventAccept, 2, 200, "nginx", srv, cli, 2))
	c.HandleEvent(ev(model.EventRetrans, 1, 0, "", netip.AddrPort{}, netip.AddrPort{}, 3))
	closeEv := ev(model.EventClose, 1, 0, "", cli, srv, 500)
	closeEv.BytesSent, closeEv.BytesRecv, closeEv.SRTTMicros = 500, 1000, 800
	c.HandleEvent(closeEv)
	c.HandleEvent(ev(model.EventClose, 2, 0, "", srv, cli, 501))

	// 2: connection whose close is lost; swept by the idle TTL.
	cli2 := ap("127.0.0.1", 41001)
	c.HandleEvent(ev(model.EventOpen, 3, 100, "curl", netip.AddrPort{}, srv, 1000))
	c.HandleEvent(ev(model.EventEstablished, 3, 0, "", cli2, srv, 1001))
	c.Tick(base.Add(3 * time.Second)) // materializes towards ext/nginx
	c.Tick(base.Add(3 * time.Minute)) // idle sweep

	// 3: failed connect with a pre-establishment reset.
	c.HandleEvent(ev(model.EventOpen, 5, 100, "curl", netip.AddrPort{}, ap("10.9.9.9", 81), 200_000))
	c.HandleEvent(ev(model.EventReset, 5, 0, "", netip.AddrPort{}, netip.AddrPort{}, 200_001))
	c.HandleEvent(ev(model.EventClose, 5, 0, "", netip.AddrPort{}, ap("10.9.9.9", 81), 200_002))

	if rec.opened != 2 {
		t.Fatalf("opened = %d, want 2", rec.opened)
	}
	if rec.closed+rec.expired != rec.opened {
		t.Fatalf("pairing broken: opened=%d closed=%d expired=%d",
			rec.opened, rec.closed, rec.expired)
	}
	if rec.expired != 1 {
		t.Fatalf("expired = %d, want 1 (the swept connection)", rec.expired)
	}
	if rec.failures != 1 {
		t.Fatalf("failures = %d, want 1", rec.failures)
	}
	if rec.retrans != 1 || rec.resets != 1 {
		t.Fatalf("health routing: retrans=%d resets=%d, want 1/1", rec.retrans, rec.resets)
	}
	if len(rec.rtts) == 0 {
		t.Fatalf("no RTT samples recorded")
	}
}

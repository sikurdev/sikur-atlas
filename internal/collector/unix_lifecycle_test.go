package collector

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/sikurdev/sikur-atlas/internal/graph"
	"github.com/sikurdev/sikur-atlas/internal/model"
	"github.com/sikurdev/sikur-atlas/internal/unixdiag"
)

func TestBuildUnixPairs(t *testing.T) {
	socks := []unixdiag.Socket{
		// Listener at a path.
		{Inode: 10, Path: "/run/reports.sock", State: unixdiag.StateListen, Type: unixdiag.TypeStream},
		// Accepted server-side socket (named, peered to client).
		{Inode: 11, Path: "/run/reports.sock", State: unixdiag.StateEstablished, Type: unixdiag.TypeStream, PeerInode: 20},
		// Client (unnamed, peered back).
		{Inode: 20, State: unixdiag.StateEstablished, Type: unixdiag.TypeStream, PeerInode: 11},
		// socketpair: both unnamed — no direction, skipped.
		{Inode: 30, State: unixdiag.StateEstablished, Type: unixdiag.TypeStream, PeerInode: 31},
		{Inode: 31, State: unixdiag.StateEstablished, Type: unixdiag.TypeStream, PeerInode: 30},
		// Unattributable client (no pid).
		{Inode: 40, State: unixdiag.StateEstablished, Type: unixdiag.TypeStream, PeerInode: 11},
	}
	inodes := map[uint64]uint32{10: 200, 11: 200, 20: 100, 30: 300, 31: 300}

	pairs, listeners := BuildUnixPairs(socks, inodes)
	if len(pairs) != 1 {
		t.Fatalf("pairs = %+v, want exactly the client->server pair", pairs)
	}
	p := pairs[0]
	if p.ClientPID != 100 || p.ServerPID != 200 || p.Path != "/run/reports.sock" {
		t.Fatalf("pair = %+v", p)
	}
	if listeners["/run/reports.sock"] != 200 {
		t.Fatalf("listeners = %v", listeners)
	}
}

func TestSyncUnixTopology(t *testing.T) {
	res := fakeResolver{
		100: {PID: 100, Comm: "python3", Exe: "/usr/local/bin/python3"},
		200: {PID: 200, Comm: "reports", Exe: "/usr/local/bin/reports"},
	}
	rec := &fakeRecorder{}
	store := graph.NewStore()
	c := New(store, res, WithRecorder(rec))

	socks := []unixdiag.Socket{
		{Inode: 10, Path: "/run/reports.sock", State: unixdiag.StateListen, Type: unixdiag.TypeStream},
		{Inode: 11, Path: "/run/reports.sock", State: unixdiag.StateEstablished, Type: unixdiag.TypeStream, PeerInode: 20},
		{Inode: 20, State: unixdiag.StateEstablished, Type: unixdiag.TypeStream, PeerInode: 11},
	}
	inodes := map[uint64]uint32{10: 200, 11: 200, 20: 100}

	c.SyncUnixTopology(socks, inodes, base)
	snap := store.Snapshot()
	if len(snap.Edges) != 1 {
		t.Fatalf("edges = %+v", snap.Edges)
	}
	e := snap.Edges[0]
	if e.Protocol != "unix" || e.Path != "/run/reports.sock" || e.ActiveConns != 1 {
		t.Fatalf("edge = %+v", e)
	}
	if e.Src != "proc:/usr/local/bin/python3" || e.Dst != "proc:/usr/local/bin/reports" {
		t.Fatalf("attribution = %+v", e)
	}
	if rec.activeDelta != 1 {
		t.Fatalf("recorder active = %d", rec.activeDelta)
	}

	// Re-scan with the same pair: no double count.
	c.SyncUnixTopology(socks, inodes, base.Add(10*time.Second))
	if got := store.Snapshot().Edges[0].ActiveConns; got != 1 {
		t.Fatalf("active after rescan = %d", got)
	}

	// Pair vanished: gauge released.
	c.SyncUnixTopology(socks[:1], map[uint64]uint32{10: 200}, base.Add(20*time.Second))
	if got := store.Snapshot().Edges[0].ActiveConns; got != 0 {
		t.Fatalf("active after vanish = %d", got)
	}
	if rec.activeDelta != 0 {
		t.Fatalf("recorder active balance = %d", rec.activeDelta)
	}
}

func TestUnixConnectEvents(t *testing.T) {
	res := fakeResolver{
		100: {PID: 100, Comm: "python3", Exe: "/usr/local/bin/python3"},
		200: {PID: 200, Comm: "reports", Exe: "/usr/local/bin/reports"},
	}
	rec := &fakeRecorder{}
	store := graph.NewStore()
	c := New(store, res, WithRecorder(rec))

	// Teach the path index via a scan.
	c.SyncUnixTopology([]unixdiag.Socket{
		{Inode: 10, Path: "/run/reports.sock", State: unixdiag.StateListen, Type: unixdiag.TypeStream},
	}, map[uint64]uint32{10: 200}, base)

	// Successful connect counts a connection towards the path owner.
	okEv := ev(model.EventUnixConnect, 55, 100, "python3", netip.AddrPort{}, netip.AddrPort{}, 100)
	okEv.Path = "/run/reports.sock"
	c.HandleEvent(okEv)

	// Refused connect to an unknown path becomes a failure towards a
	// placeholder.
	failEv := ev(model.EventUnixConnect, 56, 100, "python3", netip.AddrPort{}, netip.AddrPort{}, 200)
	failEv.Path = "/run/gone.sock"
	failEv.Code = -111
	c.HandleEvent(failEv)

	snap := store.Snapshot()
	var okEdge, failEdge *graph.Edge
	for i := range snap.Edges {
		switch snap.Edges[i].Path {
		case "/run/reports.sock":
			okEdge = &snap.Edges[i]
		case "/run/gone.sock":
			failEdge = &snap.Edges[i]
		}
	}
	if okEdge == nil || okEdge.Connections != 1 || okEdge.Dst != "proc:/usr/local/bin/reports" {
		t.Fatalf("ok edge = %+v", okEdge)
	}
	if failEdge == nil || failEdge.Failures != 1 || failEdge.Dst != "unix:/run/gone.sock" {
		t.Fatalf("fail edge = %+v", failEdge)
	}
	if rec.connects != 1 || rec.failures != 1 {
		t.Fatalf("recorder: connects=%d failures=%d", rec.connects, rec.failures)
	}
	st := c.Stats()
	if st.UnixConnects != 2 || st.UnixFailures != 1 {
		t.Fatalf("stats = %+v", st)
	}
}

func TestLifecycleAttribution(t *testing.T) {
	cid := "cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe"
	res := fakeResolver{
		300: {PID: 300, Comm: "python3", Exe: "/usr/local/bin/python3", ContainerID: cid},
		999: {PID: 999, Comm: "bash", Exe: "/bin/bash"},
	}
	rec := &fakeRecorder{}
	store := graph.NewStore()
	c := New(store, res, WithRecorder(rec))

	// The container node exists because it has traffic.
	cli := ap("172.17.0.1", 41000)
	srv := ap("172.17.0.9", 8000)
	c.HandleEvent(ev(model.EventOpen, 1, 999, "bash", netip.AddrPort{}, srv, 0))
	c.HandleEvent(ev(model.EventEstablished, 1, 0, "", cli, srv, 1))
	c.HandleEvent(ev(model.EventAccept, 2, 300, "python3", srv, cli, 2))

	// Exec inside the known container attaches.
	execEv := ev(model.EventExec, 0, 300, "python3", netip.AddrPort{}, netip.AddrPort{}, 100)
	execEv.Path = "/usr/local/bin/python3"
	c.HandleEvent(execEv)

	// Crash exit of the remembered pid attaches with a decoded signal.
	exitEv := ev(model.EventExit, 0, 300, "python3", netip.AddrPort{}, netip.AddrPort{}, 200)
	exitEv.Code = 11 // killed by SIGSEGV
	c.HandleEvent(exitEv)

	// OOM for a pid nobody knows is dropped, not misattributed.
	oomEv := ev(model.EventOOM, 0, 777777, "", netip.AddrPort{}, netip.AddrPort{}, 300)
	c.HandleEvent(oomEv)

	if len(rec.nodeEvents) != 2 {
		t.Fatalf("node events = %v", rec.nodeEvents)
	}
	if !strings.HasPrefix(rec.nodeEvents[0], "container:cafebabecafe|exec|") {
		t.Fatalf("exec event = %q", rec.nodeEvents[0])
	}
	if !strings.Contains(rec.nodeEvents[1], "|crash|") ||
		!strings.Contains(rec.nodeEvents[1], "SIGSEGV") {
		t.Fatalf("crash event = %q", rec.nodeEvents[1])
	}
	if c.Stats().LifecycleDropped != 1 {
		t.Fatalf("dropped = %d, want 1", c.Stats().LifecycleDropped)
	}
}

func TestDecodeExit(t *testing.T) {
	cases := []struct {
		code   int32
		kind   string
		substr string
	}{
		{0, LifeExit, "cleanly"},
		{256, LifeExit, "status 1"},
		{11, LifeCrash, "SIGSEGV"},
		{9, LifeExit, "signal 9"},
		{6, LifeCrash, "SIGABRT"},
		{15, LifeExit, "signal 15"},
	}
	for _, tc := range cases {
		kind, detail := decodeExit(tc.code)
		if kind != tc.kind || !strings.Contains(detail, tc.substr) {
			t.Fatalf("decodeExit(%d) = %q %q, want %s/%s", tc.code, kind, detail, tc.kind, tc.substr)
		}
	}
}

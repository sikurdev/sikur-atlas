package lens

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/sikurdev/sikur-atlas/internal/appview"
	"github.com/sikurdev/sikur-atlas/internal/graph"
	"github.com/sikurdev/sikur-atlas/internal/history"
)

// TestRunAgainstRecordedHistory drives a real history store through a
// scripted incident — steady traffic, then the dependency's process
// exits and everything it served goes quiet — and checks that Run
// assembles the recorded rows into a resolved investigation.
func TestRunAgainstRecordedHistory(t *testing.T) {
	g := graph.NewStore()
	dbPath := filepath.Join(t.TempDir(), "history.db")
	st, err := history.Open(dbPath, g, history.WithSpans(10*time.Second, 60*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	orders := graph.NodeSpec{ID: "proc:/bin/orders", Kind: graph.NodeProcess, Label: "orders", Exe: "/bin/orders", PID: 10}
	inventory := graph.NodeSpec{ID: "proc:/bin/inventory", Kind: graph.NodeProcess, Label: "inventory", Exe: "/bin/inventory", PID: 20}
	edgeID := "proc:/bin/orders->proc:/bin/inventory:8000"

	stopAt := int64(120)
	var exitRecorded bool
	for off := int64(0); off < 300; off += 10 {
		now := t0.Add(time.Duration(off) * time.Second)
		if off < stopAt {
			// Steady request traffic while inventory lives.
			g.ObserveConnection(orders, inventory, 8000, now.Add(time.Second))
			st.EdgeOpened(edgeID, now.Add(time.Second))
			st.EdgeClosed(edgeID, 100, 200, 1000, now.Add(2*time.Second))
			g.SyncListeners([]graph.ListenerSet{{Spec: inventory, Ports: []uint16{8000}}}, now)
		} else {
			if !exitRecorded {
				exitRecorded = true
				st.NodeEvent(inventory.ID, "exit", 20, "killed by signal 15", t0.Add(time.Duration(stopAt+2)*time.Second))
			}
			// Inventory is gone: the listen scan no longer sees it.
			g.SyncListeners(nil, now)
		}
		if err := st.Flush(now.Add(10 * time.Second)); err != nil {
			t.Fatal(err)
		}
	}

	rep, err := Run(st, t0, t0.Add(300*time.Second), "", appview.Options{})
	if err != nil {
		t.Fatal(err)
	}

	if rep.Origin == nil {
		t.Fatalf("origin unresolved: %q; findings: %+v", rep.Unresolved, rep.Findings)
	}
	if rep.Origin.Service != "svc:proc:inventory" {
		t.Fatalf("origin = %s, want svc:proc:inventory", rep.Origin.Service)
	}
	exit := findKind(rep.Findings, KindExit)
	if exit == nil || exit.Service != "svc:proc:inventory" {
		t.Fatalf("exit finding missing: %+v", rep.Findings)
	}
	stop := findKind(rep.Findings, KindTrafficStop)
	if stop == nil || stop.EdgeDst != "svc:proc:inventory" {
		t.Fatalf("traffic-stop finding missing: %+v", rep.Findings)
	}
	gone := findKind(rep.Findings, KindServiceGone)
	if gone == nil || gone.Service != "svc:proc:inventory" {
		t.Fatalf("service-gone finding missing: %+v", rep.Findings)
	}
	if len(rep.BlastRadius.Edges) != 1 {
		t.Fatalf("blast radius edges = %v", rep.BlastRadius.Edges)
	}
	for _, r := range rep.Recovery {
		if r.RecoveredAt != nil {
			t.Fatalf("nothing recovered in this scenario: %+v", r)
		}
	}
	// Deterministic across runs over the same recorded data.
	rep2, err := Run(st, t0, t0.Add(300*time.Second), "", appview.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if rep2.Origin == nil || rep2.Origin.Service != rep.Origin.Service || len(rep2.Findings) != len(rep.Findings) {
		t.Fatal("Run is not deterministic over the same store")
	}
}

// TestRunUnflushedWindow investigates a window whose evidence is still
// in memory (nothing flushed): the pending-state merge must surface it.
func TestRunUnflushedWindow(t *testing.T) {
	g := graph.NewStore()
	dbPath := filepath.Join(t.TempDir(), "history.db")
	st, err := history.Open(dbPath, g, history.WithSpans(10*time.Second, 60*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	a := graph.NodeSpec{ID: "proc:/bin/a", Kind: graph.NodeProcess, Label: "a", Exe: "/bin/a"}
	b := graph.NodeSpec{ID: "proc:/bin/b", Kind: graph.NodeProcess, Label: "b", Exe: "/bin/b"}
	edge := "proc:/bin/a->proc:/bin/b:9000"
	g.ObserveConnection(a, b, 9000, t0.Add(5*time.Second))
	st.EdgeOpened(edge, t0.Add(5*time.Second))
	st.EdgeFailure(edge, t0.Add(25*time.Second))
	// One flush so node/edge metadata exists for the mapping; the
	// failure bucket at t0+20 is already flushed by it, but the later
	// one stays pending.
	if err := st.Flush(t0.Add(40 * time.Second)); err != nil {
		t.Fatal(err)
	}
	st.EdgeFailure(edge, t0.Add(45*time.Second)) // pending only

	rep, err := Run(st, t0, t0.Add(60*time.Second), "", appview.Options{})
	if err != nil {
		t.Fatal(err)
	}
	fs := findKind(rep.Findings, KindFailuresStart)
	if fs == nil {
		t.Fatalf("failures-start not detected from mixed flushed+pending rows: %+v", rep.Findings)
	}
}

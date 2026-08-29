package tui

import (
	"strings"
	"testing"
	"time"
)

func demoGraph() AppGraph {
	node := func(id, label, category, kind string, m *NodeMetrics) AppNode {
		return AppNode{ID: id, Label: label, Category: category, Kind: kind,
			Members: []string{"raw-" + label}, MemberCount: 1, Metrics: m}
	}
	return AppGraph{
		Nodes: []AppNode{
			node("svc:compose:d/gateway", "gateway", "app", "compose",
				&NodeMetrics{WindowSecs: 10, CPUMillis: 500, RSSBytes: 40 << 20}),
			node("svc:compose:d/orders", "orders", "app", "compose",
				&NodeMetrics{WindowSecs: 10, CPUMillis: 2500, RSSBytes: 120 << 20, OOMKills: 1}),
			node("svc:compose:d/cache", "cache", "app", "compose",
				&NodeMetrics{WindowSecs: 10, CPUMillis: 100, RSSBytes: 10 << 20}),
			node("svc:proc:dockerd", "dockerd", "system", "process", nil),
			node("svc:external", "external", "external", "external", nil),
		},
		Edges: []AppEdge{
			{ID: "e1", Src: "svc:compose:d/gateway", Dst: "svc:compose:d/orders",
				DstPort: 8000, Protocol: "tcp", ActiveConns: 2,
				Window: &EdgeWindow{Seconds: 60, Opens: 30, RTTAvgUs: 1500}},
			{ID: "e2", Src: "svc:compose:d/orders", Dst: "svc:compose:d/cache",
				Protocol: "unix", Path: "/run/cache.sock", ActiveConns: 1,
				Window: &EdgeWindow{Seconds: 60, Opens: 60, Failures: 5}},
			{ID: "e3", Src: "svc:proc:dockerd", Dst: "svc:external",
				DstPort: 443, Protocol: "tcp"},
		},
	}
}

func TestBuildRows(t *testing.T) {
	rows := BuildRows(demoGraph(), "", false, "")
	if len(rows) != 3 {
		t.Fatalf("rows = %d, want 3 (system+external hidden): %+v", len(rows), rows)
	}
	byLabel := map[string]Row{}
	for _, r := range rows {
		byLabel[r.Label] = r
	}
	orders := byLabel["orders"]
	if orders.CPUPct != 25 {
		t.Fatalf("orders cpu%% = %v, want 25", orders.CPUPct)
	}
	if orders.Fails != 5 || orders.OOMs != 1 {
		t.Fatalf("orders health = %+v", orders)
	}
	if orders.Deps != 1 || orders.Callers != 1 {
		t.Fatalf("orders degree = %+v", orders)
	}
	gw := byLabel["gateway"]
	if gw.RTTUs != 1500 || gw.Rate != 30 {
		t.Fatalf("gateway = %+v", gw)
	}

	// System toggle brings dockerd in.
	if rows := BuildRows(demoGraph(), "", true, ""); len(rows) != 4 {
		t.Fatalf("with system rows = %d", len(rows))
	}
	// Filter narrows.
	if rows := BuildRows(demoGraph(), "cach", false, ""); len(rows) != 1 || rows[0].Label != "cache" {
		t.Fatalf("filtered = %+v", rows)
	}
}

func TestFocusClosure(t *testing.T) {
	rows := BuildRows(demoGraph(), "", false, "svc:compose:d/orders")
	labels := map[string]bool{}
	for _, r := range rows {
		labels[r.Label] = true
	}
	if !labels["gateway"] || !labels["orders"] || !labels["cache"] {
		t.Fatalf("closure rows = %v", labels)
	}
}

func TestSortRows(t *testing.T) {
	rows := BuildRows(demoGraph(), "", false, "")
	SortRows(rows, SortCPU)
	if rows[0].Label != "orders" {
		t.Fatalf("cpu sort first = %s", rows[0].Label)
	}
	// Failures attribute to both ends of the failing edge (caller and
	// target); the name tiebreak puts cache first.
	SortRows(rows, SortFail)
	if rows[0].Label != "cache" || rows[0].Fails != 5 {
		t.Fatalf("fail sort first = %s (%d)", rows[0].Label, rows[0].Fails)
	}
	SortRows(rows, SortName)
	if rows[0].Label != "cache" {
		t.Fatalf("name sort first = %s", rows[0].Label)
	}
	if NextSort(SortCPU) != SortRSS || NextSort(SortName) != SortCPU {
		t.Fatal("sort cycle broken")
	}
}

func TestRenderFrame(t *testing.T) {
	snap := Snapshot{Graph: demoGraph()}
	snap.Meta.Version = "0.3.0-test"
	snap.Meta.Kernel = "Linux test"
	snap.Life = []LifeEvent{
		{NodeID: "raw-orders", Kind: "oom", Detail: "pid 42 chosen by the OOM killer",
			Time: time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)},
	}
	rows := BuildRows(snap.Graph, "", false, "")
	SortRows(rows, SortCPU)
	st := &State{Snapshot: snap, Rows: rows, Plain: true, Width: 110, Height: 40}

	frame := Render(st)
	for _, want := range []string{
		"ATLAS TOP", "0.3.0-test", "SERVICE", "CPU%", "RSS", "FAIL",
		"orders", "gateway", "cache", "25.0", "120M",
	} {
		if !strings.Contains(frame, want) {
			t.Fatalf("frame missing %q:\n%s", want, frame)
		}
	}
	if strings.Contains(frame, "dockerd") {
		t.Fatalf("system service leaked into default frame")
	}
	if strings.Contains(frame, "\x1b[") {
		t.Fatalf("plain frame contains ANSI escapes")
	}

	// Drill panel shows dependencies with the unix path and lifecycle.
	st.Drill = true
	st.Selected = 0 // orders (cpu sort)
	frame = Render(st)
	for _, want := range []string{
		"── orders ──", "depends on:", "/run/cache.sock", "[unix]",
		"called by:", "lifecycle", "oom", "OOM killer",
	} {
		if !strings.Contains(frame, want) {
			t.Fatalf("drill missing %q:\n%s", want, frame)
		}
	}
}

func TestRenderError(t *testing.T) {
	st := &State{Err: errFake{}, Plain: true, Width: 90, Height: 20}
	frame := Render(st)
	if !strings.Contains(frame, "cannot reach agent") ||
		!strings.Contains(frame, "sudo atlas") {
		t.Fatalf("error frame:\n%s", frame)
	}
}

type errFake struct{}

func (errFake) Error() string { return "connection refused" }

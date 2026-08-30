package appview

import (
	"testing"
	"time"

	"github.com/sikurdev/sikur-atlas/internal/graph"
)

var t0 = time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)

func demoSnapshot() graph.Snapshot {
	mk := func(id string, kind graph.NodeKind, label string) graph.Node {
		return graph.Node{ID: id, Kind: kind, Label: label, FirstSeen: t0, LastSeen: t0}
	}
	gw := mk("container:aaa", graph.NodeContainer, "atlas-demo-gateway")
	gw.ComposeProject, gw.ComposeService = "atlas-demo", "gateway"
	gw.ContainerName = "atlas-demo-gateway"
	gw.ListenPorts = []uint16{8080}

	orders1 := mk("container:bbb", graph.NodeContainer, "atlas-demo-orders-1")
	orders1.ComposeProject, orders1.ComposeService = "atlas-demo", "orders"
	orders2 := mk("container:bbc", graph.NodeContainer, "atlas-demo-orders-2")
	orders2.ComposeProject, orders2.ComposeService = "atlas-demo", "orders"

	plain := mk("container:ccc", graph.NodeContainer, "lonely")
	plain.ContainerName = "lonely"

	dockerd := mk("proc:/usr/bin/dockerd", graph.NodeProcess, "dockerd")
	dockerd.Exe = "/usr/bin/dockerd"
	atlasSelf := mk("proc:/opt/atlas/bin/atlas", graph.NodeProcess, "atlas")
	atlasSelf.Exe = "/opt/atlas/bin/atlas"
	app := mk("proc:/home/u/myapi", graph.NodeProcess, "myapi")
	app.Exe = "/home/u/myapi"

	ext1 := mk("ext:93.184.216.34", graph.NodeExternal, "93.184.216.34")
	ext2 := mk("ext:198.51.100.7", graph.NodeExternal, "198.51.100.7")

	edge := func(src, dst string, port uint16, conns uint64) graph.Edge {
		return graph.Edge{
			ID: src + "->" + dst + ":" + portString(port), Src: src, Dst: dst,
			DstPort: port, Protocol: "tcp", Connections: conns,
			FirstSeen: t0, LastSeen: t0,
		}
	}
	e1 := edge("container:aaa", "container:bbb", 8000, 10)
	e2 := edge("container:aaa", "container:bbc", 8000, 6)
	e3 := edge("proc:/usr/bin/dockerd", "ext:93.184.216.34", 443, 3)
	e4 := edge("proc:/usr/bin/dockerd", "ext:198.51.100.7", 443, 2)
	e5 := edge("proc:/home/u/myapi", "container:ccc", 6379, 4)
	e5.Failures = 2

	return graph.Snapshot{
		GeneratedAt: t0,
		Nodes:       []graph.Node{gw, orders1, orders2, plain, dockerd, atlasSelf, app, ext1, ext2},
		Edges:       []graph.Edge{e1, e2, e3, e4, e5},
	}
}

func nodeByID(g Graph, id string) *Node {
	for i := range g.Nodes {
		if g.Nodes[i].ID == id {
			return &g.Nodes[i]
		}
	}
	return nil
}

func TestProjectGroupsAndClassifies(t *testing.T) {
	g := Project(demoSnapshot(), Options{SelfExe: "/opt/atlas/bin/atlas"})

	// Compose replicas merge into one service.
	orders := nodeByID(g, "svc:compose:atlas-demo/orders")
	if orders == nil || orders.MemberCount != 2 {
		t.Fatalf("orders service = %+v", orders)
	}
	if orders.Category != CategoryApp || orders.Label != "orders" {
		t.Fatalf("orders = %+v", orders)
	}

	gw := nodeByID(g, "svc:compose:atlas-demo/gateway")
	if gw == nil || len(gw.ListenPorts) != 1 || gw.ListenPorts[0] != 8080 {
		t.Fatalf("gateway = %+v", gw)
	}

	// Non-compose container keeps its own node.
	if n := nodeByID(g, "svc:container:container:ccc"); n == nil || n.Label != "lonely" {
		t.Fatalf("plain container = %+v", n)
	}

	// System, self and app classification.
	if n := nodeByID(g, "svc:proc:dockerd"); n == nil || n.Category != CategorySystem {
		t.Fatalf("dockerd = %+v", n)
	}
	if n := nodeByID(g, "svc:proc:atlas"); n == nil || n.Category != CategoryAtlas {
		t.Fatalf("atlas self = %+v", n)
	}
	if n := nodeByID(g, "svc:proc:myapi"); n == nil || n.Category != CategoryApp {
		t.Fatalf("myapi = %+v", n)
	}

	// External endpoints collapse into one aggregate.
	ext := nodeByID(g, ExternalID)
	if ext == nil || ext.MemberCount != 2 || ext.Category != CategoryExternal {
		t.Fatalf("external = %+v", ext)
	}
}

func TestProjectAggregatesEdges(t *testing.T) {
	g := Project(demoSnapshot(), Options{})

	// gateway -> orders replicas: two raw edges, one service edge.
	var found *Edge
	for i := range g.Edges {
		if g.Edges[i].Src == "svc:compose:atlas-demo/gateway" &&
			g.Edges[i].Dst == "svc:compose:atlas-demo/orders" {
			found = &g.Edges[i]
		}
	}
	if found == nil {
		t.Fatalf("gateway->orders edge missing: %+v", g.Edges)
	}
	if found.Connections != 16 || len(found.RawEdges) != 2 {
		t.Fatalf("aggregation wrong: %+v", found)
	}

	// dockerd -> external: two raw endpoints, one aggregate edge.
	var extEdge *Edge
	for i := range g.Edges {
		if g.Edges[i].Src == "svc:proc:dockerd" && g.Edges[i].Dst == ExternalID {
			extEdge = &g.Edges[i]
		}
	}
	if extEdge == nil || extEdge.Connections != 5 || len(extEdge.RawEdges) != 2 {
		t.Fatalf("external aggregation wrong: %+v", extEdge)
	}

	// Failures survive projection.
	var failEdge *Edge
	for i := range g.Edges {
		if g.Edges[i].Dst == "svc:container:container:ccc" {
			failEdge = &g.Edges[i]
		}
	}
	if failEdge == nil || failEdge.Failures != 2 {
		t.Fatalf("failures lost: %+v", failEdge)
	}
}

func TestProjectIsDeterministic(t *testing.T) {
	a := Project(demoSnapshot(), Options{})
	b := Project(demoSnapshot(), Options{})
	if len(a.Nodes) != len(b.Nodes) || len(a.Edges) != len(b.Edges) {
		t.Fatal("nondeterministic sizes")
	}
	for i := range a.Nodes {
		if a.Nodes[i].ID != b.Nodes[i].ID {
			t.Fatalf("node order differs at %d: %s vs %s", i, a.Nodes[i].ID, b.Nodes[i].ID)
		}
	}
	for i := range a.Edges {
		if a.Edges[i].ID != b.Edges[i].ID {
			t.Fatalf("edge order differs at %d", i)
		}
	}
}

func TestComputeDiffTopologyChange(t *testing.T) {
	snapA := demoSnapshot()
	a := Project(snapA, Options{})

	// Era B: the "lonely" container is gone (stopped) and a new compose
	// service appeared.
	snapB := demoSnapshot()
	var nodesB []graph.Node
	for _, n := range snapB.Nodes {
		if n.ID != "container:ccc" {
			nodesB = append(nodesB, n)
		}
	}
	newSvc := graph.Node{
		ID: "container:ddd", Kind: graph.NodeContainer, Label: "atlas-demo-reports",
		ComposeProject: "atlas-demo", ComposeService: "reports",
		FirstSeen: t0.Add(time.Hour), LastSeen: t0.Add(time.Hour),
	}
	nodesB = append(nodesB, newSvc)
	snapB.Nodes = nodesB
	var edgesB []graph.Edge
	for _, e := range snapB.Edges {
		if e.Dst != "container:ccc" {
			edgesB = append(edgesB, e)
		}
	}
	snapB.Edges = edgesB
	b := Project(snapB, Options{})

	d := ComputeDiff(a, b)
	if len(d.RemovedNodes) != 1 || d.RemovedNodes[0].ID != "svc:container:container:ccc" {
		t.Fatalf("removed = %+v", d.RemovedNodes)
	}
	if len(d.AddedNodes) != 1 || d.AddedNodes[0].ID != "svc:compose:atlas-demo/reports" {
		t.Fatalf("added = %+v", d.AddedNodes)
	}
	if len(d.RemovedEdges) != 1 {
		t.Fatalf("removed edges = %+v", d.RemovedEdges)
	}
}

func TestComputeDiffHealthChange(t *testing.T) {
	snapA := demoSnapshot()
	snapB := demoSnapshot()
	// The gateway->orders edges collapse to one service edge; era B has
	// failures where era A had none, and RTT tripled past the floor.
	for i := range snapB.Edges {
		if snapB.Edges[i].Dst == "container:bbb" {
			snapB.Edges[i].Failures = 9
			snapB.Edges[i].LastRTTUs = 30000
		}
	}
	for i := range snapA.Edges {
		if snapA.Edges[i].Dst == "container:bbb" {
			snapA.Edges[i].LastRTTUs = 2000
		}
	}
	d := ComputeDiff(Project(snapA, Options{}), Project(snapB, Options{}))
	if len(d.ChangedEdges) != 1 {
		t.Fatalf("changed = %+v", d.ChangedEdges)
	}
	ch := d.ChangedEdges[0]
	if ch.Edge.Dst != "svc:compose:atlas-demo/orders" {
		t.Fatalf("wrong edge: %+v", ch.Edge)
	}
	hasFailures, hasRTT := false, false
	for _, c := range ch.Changes {
		if c == "failures" {
			hasFailures = true
		}
		if c == "rtt" {
			hasRTT = true
		}
	}
	if !hasFailures || !hasRTT {
		t.Fatalf("changes = %v, want failures+rtt", ch.Changes)
	}
	if ch.AFailures != 0 || ch.Edge.Failures != 9 {
		t.Fatalf("failure delta wrong: %+v", ch)
	}
}

// Small metric wobbles must not read as changes.
func TestComputeDiffIgnoresNoise(t *testing.T) {
	snapA := demoSnapshot()
	snapB := demoSnapshot()
	for i := range snapB.Edges {
		snapB.Edges[i].Connections += 1 // below the rate floor
	}
	d := ComputeDiff(Project(snapA, Options{}), Project(snapB, Options{}))
	if len(d.ChangedEdges) != 0 || len(d.AddedEdges) != 0 || len(d.RemovedEdges) != 0 {
		t.Fatalf("noise reported as change: %+v", d)
	}
}

package appview

import (
	"github.com/sikurdev/sikur-atlas/internal/graph"
	"slices"
	"strings"
	"time"
)

// Diff is the deterministic answer to "what changed between A and B",
// computed from recorded evidence only.
type Diff struct {
	A            time.Time    `json:"a"`
	B            time.Time    `json:"b"`
	AddedNodes   []Node       `json:"addedNodes"`
	RemovedNodes []Node       `json:"removedNodes"`
	AddedEdges   []Edge       `json:"addedEdges"`
	RemovedEdges []Edge       `json:"removedEdges"`
	ChangedEdges []EdgeChange `json:"changedEdges"`
	ChangedNodes []NodeChange `json:"changedNodes"`
	// Lifecycle lists recorded exec/exit/crash/oom events between the
	// two moments, grouped to services by the API layer.
	Lifecycle []LifecycleEntry `json:"lifecycle"`
}

// NodeChange is a service present at both moments whose resources moved
// meaningfully.
type NodeChange struct {
	Node    Node     `json:"node"` // B-side values
	Changes []string `json:"changes"`
	// A-side values for delta rendering.
	ACPUMillis uint64 `json:"aCpuMillis"`
	ARSSBytes  uint64 `json:"aRssBytes"`
}

// LifecycleEntry is one lifecycle event mapped onto the service graph.
type LifecycleEntry struct {
	Node   string    `json:"node"`  // service id
	Label  string    `json:"label"` // service label
	Kind   string    `json:"kind"`  // exec | exit | crash | oom
	Detail string    `json:"detail"`
	Time   time.Time `json:"time"`
}

// EdgeChange is an edge present at both moments whose health moved
// meaningfully.
type EdgeChange struct {
	Edge Edge `json:"edge"` // B-side values
	// Changes name what moved: "failures", "resets", "retransmits",
	// "rtt", "rate", "bytes".
	Changes []string `json:"changes"`
	// A-side values for the UI to show deltas.
	AConnections uint64 `json:"aConnections"`
	AFailures    uint64 `json:"aFailures"`
	AResets      uint64 `json:"aResets"`
	ARetransmits uint64 `json:"aRetransmits"`
	ARTTAvgUs    uint32 `json:"aRttAvgUs"`
	ABytesSent   uint64 `json:"aBytesSent"`
	ABytesRecv   uint64 `json:"aBytesRecv"`
}

// Change detection thresholds: a metric counts as changed when it moved
// by at least half its old value AND by an absolute floor, so tiny
// wobbles don't read as incidents. Documented in docs/architecture.md.
const (
	relThreshold = 0.5
	rttFloorUs   = 5000 // 5 ms
	rateFloor    = 5    // connections per window
	bytesFloor   = 64 * 1024
)

// ComputeDiff compares two projected views (A = earlier, B = later).
func ComputeDiff(a, b Graph) Diff {
	d := Diff{A: a.GeneratedAt, B: b.GeneratedAt}

	aNodes := make(map[string]Node, len(a.Nodes))
	for _, n := range a.Nodes {
		aNodes[n.ID] = n
	}
	bNodes := make(map[string]Node, len(b.Nodes))
	for _, n := range b.Nodes {
		bNodes[n.ID] = n
	}
	for _, n := range b.Nodes {
		if _, ok := aNodes[n.ID]; !ok {
			d.AddedNodes = append(d.AddedNodes, n)
		}
	}
	for _, n := range a.Nodes {
		if _, ok := bNodes[n.ID]; !ok {
			d.RemovedNodes = append(d.RemovedNodes, n)
		}
	}

	aEdges := make(map[string]Edge, len(a.Edges))
	for _, e := range a.Edges {
		aEdges[e.ID] = e
	}
	bEdges := make(map[string]Edge, len(b.Edges))
	for _, e := range b.Edges {
		bEdges[e.ID] = e
	}
	for _, e := range b.Edges {
		ae, ok := aEdges[e.ID]
		if !ok {
			d.AddedEdges = append(d.AddedEdges, e)
			continue
		}
		if changes := edgeChanges(ae, e); len(changes) > 0 {
			d.ChangedEdges = append(d.ChangedEdges, EdgeChange{
				Edge:         e,
				Changes:      changes,
				AConnections: ae.Connections,
				AFailures:    ae.Failures,
				AResets:      ae.Resets,
				ARetransmits: ae.Retransmits,
				ARTTAvgUs:    windowRTT(ae),
				ABytesSent:   ae.BytesSent,
				ABytesRecv:   ae.BytesRecv,
			})
		}
	}
	for _, e := range a.Edges {
		if _, ok := bEdges[e.ID]; !ok {
			d.RemovedEdges = append(d.RemovedEdges, e)
		}
	}

	for _, n := range b.Nodes {
		an, ok := aNodes[n.ID]
		if !ok || an.Metrics == nil || n.Metrics == nil {
			continue
		}
		if changes := nodeChanges(*an.Metrics, *n.Metrics); len(changes) > 0 {
			d.ChangedNodes = append(d.ChangedNodes, NodeChange{
				Node:       n,
				Changes:    changes,
				ACPUMillis: an.Metrics.CPUMillis,
				ARSSBytes:  an.Metrics.RSSBytes,
			})
		}
	}

	sortDiff(&d)
	return d
}

// Node metric thresholds: same relative rule as edges, with resource
// floors (CPU 250 ms per window, RSS 32 MiB, throttling 100 ms). New
// OOM kills always count.
const (
	cpuFloorMillis  = 250
	rssFloorBytes   = 32 * 1024 * 1024
	throttleFloorUs = 100_000
)

func nodeChanges(a, b graph.NodeMetrics) []string {
	var out []string
	if b.OOMKills > a.OOMKills {
		out = append(out, "oomkill")
	}
	if moved(float64(a.CPUMillis), float64(b.CPUMillis), cpuFloorMillis) {
		out = append(out, "cpu")
	}
	if moved(float64(a.RSSBytes), float64(b.RSSBytes), rssFloorBytes) {
		out = append(out, "rss")
	}
	if moved(float64(a.ThrottledUs), float64(b.ThrottledUs), throttleFloorUs) {
		out = append(out, "throttle")
	}
	return out
}

func windowRTT(e Edge) uint32 {
	if e.Window != nil {
		return e.Window.RTTAvgUs
	}
	return e.LastRTTUs
}

func edgeChanges(a, b Edge) []string {
	var out []string
	// New trouble is always a change, regardless of magnitude.
	if b.Failures > a.Failures && a.Failures == 0 {
		out = append(out, "failures")
	} else if moved(float64(a.Failures), float64(b.Failures), 1) {
		out = append(out, "failures")
	}
	if b.Resets > a.Resets && a.Resets == 0 {
		out = append(out, "resets")
	} else if moved(float64(a.Resets), float64(b.Resets), 1) {
		out = append(out, "resets")
	}
	if moved(float64(a.Retransmits), float64(b.Retransmits), 3) {
		out = append(out, "retransmits")
	}
	if moved(float64(windowRTT(a)), float64(windowRTT(b)), rttFloorUs) {
		out = append(out, "rtt")
	}
	if moved(float64(a.Connections), float64(b.Connections), rateFloor) {
		out = append(out, "rate")
	}
	if moved(float64(a.BytesSent+a.BytesRecv), float64(b.BytesSent+b.BytesRecv), bytesFloor) {
		out = append(out, "bytes")
	}
	return out
}

// moved reports whether v changed by both the relative threshold and an
// absolute floor.
func moved(a, b, floor float64) bool {
	diff := b - a
	if diff < 0 {
		diff = -diff
	}
	if diff < floor {
		return false
	}
	base := a
	if base == 0 {
		return true // from nothing to >= floor
	}
	return diff/base >= relThreshold
}

func sortDiff(d *Diff) {
	byNodeID := func(a, b Node) int { return strings.Compare(a.ID, b.ID) }
	byEdgeID := func(a, b Edge) int { return strings.Compare(a.ID, b.ID) }
	slices.SortFunc(d.AddedNodes, byNodeID)
	slices.SortFunc(d.RemovedNodes, byNodeID)
	slices.SortFunc(d.AddedEdges, byEdgeID)
	slices.SortFunc(d.RemovedEdges, byEdgeID)
	slices.SortFunc(d.ChangedEdges, func(a, b EdgeChange) int {
		return strings.Compare(a.Edge.ID, b.Edge.ID)
	})
	slices.SortFunc(d.ChangedNodes, func(a, b NodeChange) int {
		return strings.Compare(a.Node.ID, b.Node.ID)
	})
	slices.SortFunc(d.Lifecycle, func(a, b LifecycleEntry) int {
		if !a.Time.Equal(b.Time) {
			if a.Time.Before(b.Time) {
				return -1
			}
			return 1
		}
		return strings.Compare(a.Node, b.Node)
	})
}

// Package appview projects a raw snapshot (live or reconstructed) into
// the service-level Application View: containers group into their
// Docker Compose services, host processes group by executable and are
// classified app vs system, and external endpoints collapse into one
// aggregate. The projection is a pure function, so live view, Replay
// and Compare all share one code path.
package appview

import (
	"path"
	"slices"
	"strings"
	"time"

	"github.com/sikurdev/sikur-atlas/internal/graph"
)

// Category classifies service nodes for default visibility.
type Category string

const (
	// CategoryApp is what the user is investigating: their services.
	CategoryApp Category = "app"
	// CategorySystem is host infrastructure noise (dockerd, systemd, …),
	// hidden by default.
	CategorySystem Category = "system"
	// CategoryExternal is the aggregate of off-host endpoints.
	CategoryExternal Category = "external"
	// CategoryAtlas is the agent observing itself.
	CategoryAtlas Category = "atlas"
)

// Node is one service in the application view.
type Node struct {
	ID          string    `json:"id"`
	Label       string    `json:"label"`
	Category    Category  `json:"category"`
	Kind        string    `json:"kind"` // compose | container | process | external
	Members     []string  `json:"members"`
	MemberCount int       `json:"memberCount"`
	Image       string    `json:"image,omitempty"`
	Exe         string    `json:"exe,omitempty"`
	ListenPorts []uint16  `json:"listenPorts,omitempty"`
	FirstSeen   time.Time `json:"firstSeen"`
	LastSeen    time.Time `json:"lastSeen"`
	// Metrics aggregates member resources: deltas and RSS summed,
	// PSI at the member maximum.
	Metrics *graph.NodeMetrics `json:"metrics,omitempty"`
}

// Edge is aggregated communication between two services on one port
// (TCP) or one socket path (unix).
type Edge struct {
	ID          string            `json:"id"`
	Src         string            `json:"src"`
	Dst         string            `json:"dst"`
	DstPort     uint16            `json:"dstPort"`
	Protocol    string            `json:"protocol"`
	Path        string            `json:"path,omitempty"`
	Connections uint64            `json:"connections"`
	ActiveConns int64             `json:"activeConns"`
	SeededConns int64             `json:"seededConns,omitempty"`
	BytesSent   uint64            `json:"bytesSent"`
	BytesRecv   uint64            `json:"bytesRecv"`
	Failures    uint64            `json:"failures,omitempty"`
	Resets      uint64            `json:"resets,omitempty"`
	Retransmits uint64            `json:"retransmits,omitempty"`
	LastRTTUs   uint32            `json:"lastRttUs,omitempty"`
	FirstSeen   time.Time         `json:"firstSeen"`
	LastSeen    time.Time         `json:"lastSeen"`
	Window      *graph.EdgeWindow `json:"window,omitempty"`
	// RawEdges are the underlying raw edge ids (drill-down).
	RawEdges []string `json:"rawEdges"`
}

// Graph is the application view of one moment.
type Graph struct {
	GeneratedAt time.Time `json:"generatedAt"`
	Nodes       []Node    `json:"nodes"`
	Edges       []Edge    `json:"edges"`
}

// systemExes classifies well-known host infrastructure by executable
// basename. Everything else on the host defaults to app (visible), so a
// user's own binaries are never hidden.
var systemExes = map[string]bool{
	"dockerd": true, "docker-proxy": true, "containerd": true,
	"containerd-shim-runc-v2": true, "runc": true,
	"systemd": true, "systemd-resolved": true, "systemd-journald": true,
	"systemd-logind": true, "systemd-networkd": true, "systemd-timesyncd": true,
	"sshd": true, "chronyd": true, "ntpd": true, "rsyslogd": true,
	"snapd": true, "packagekitd": true, "polkitd": true, "cron": true,
	"agetty": true, "dbus-daemon": true, "NetworkManager": true,
	"unattended-upgr": true, "php-agent": true, "provisioner": true,
	"waagent": true, "python3-waagent": true, "google_guest_ag": true,
	"amazon-ssm-agen": true, "walinuxagent": true, "Runner.Worker": true,
	"Runner.Listener": true, "hosted-compute-agent": true,
	"node-exporter": true,
}

// Options tune the projection.
type Options struct {
	// SelfExe marks the Atlas agent's own executable so it can classify
	// itself; empty disables self-detection.
	SelfExe string
}

// ExternalID is the aggregate external node's id. Exported for the
// Incident Lens, whose rules treat the external aggregate specially
// (evidence about it can be neither explained nor refuted locally).
const ExternalID = "svc:external"

// Project computes the application view of snap.
func Project(snap graph.Snapshot, opts Options) Graph {
	nodeToSvc := make(map[string]string, len(snap.Nodes))
	svcNodes := make(map[string]*Node)

	var externalMembers []string
	var extFirst, extLast time.Time

	for i := range snap.Nodes {
		n := &snap.Nodes[i]
		if n.Kind == graph.NodeExternal {
			nodeToSvc[n.ID] = ExternalID
			externalMembers = append(externalMembers, n.ID)
			if extFirst.IsZero() || n.FirstSeen.Before(extFirst) {
				extFirst = n.FirstSeen
			}
			if n.LastSeen.After(extLast) {
				extLast = n.LastSeen
			}
			continue
		}
		id, label, kind, category := classify(n, opts)
		nodeToSvc[n.ID] = id
		svc, ok := svcNodes[id]
		if !ok {
			svc = &Node{
				ID: id, Label: label, Category: category, Kind: kind,
				FirstSeen: n.FirstSeen, LastSeen: n.LastSeen,
			}
			svcNodes[id] = svc
		}
		svc.Members = append(svc.Members, n.ID)
		if n.Image != "" && svc.Image == "" {
			svc.Image = n.Image
		}
		if n.Exe != "" && svc.Exe == "" {
			svc.Exe = n.Exe
		}
		for _, p := range n.ListenPorts {
			if !slices.Contains(svc.ListenPorts, p) {
				svc.ListenPorts = append(svc.ListenPorts, p)
			}
		}
		if n.FirstSeen.Before(svc.FirstSeen) {
			svc.FirstSeen = n.FirstSeen
		}
		if n.LastSeen.After(svc.LastSeen) {
			svc.LastSeen = n.LastSeen
		}
		if n.Metrics != nil {
			svc.Metrics = mergeMetrics(svc.Metrics, n.Metrics)
		}
	}
	if len(externalMembers) > 0 {
		slices.Sort(externalMembers)
		svcNodes[ExternalID] = &Node{
			ID:        ExternalID,
			Label:     "external",
			Category:  CategoryExternal,
			Kind:      "external",
			Members:   externalMembers,
			FirstSeen: extFirst,
			LastSeen:  extLast,
		}
	}

	svcEdges := make(map[string]*Edge)
	for i := range snap.Edges {
		e := &snap.Edges[i]
		src, ok1 := nodeToSvc[e.Src]
		dst, ok2 := nodeToSvc[e.Dst]
		if !ok1 || !ok2 || src == dst {
			// Intra-service traffic (e.g. a service talking to itself)
			// carries no dependency information at this level.
			continue
		}
		var id string
		if e.Protocol == "unix" {
			id = src + "->" + dst + ":unix:" + e.Path
		} else {
			id = src + "->" + dst + ":" + portString(e.DstPort)
		}
		se, ok := svcEdges[id]
		if !ok {
			se = &Edge{
				ID: id, Src: src, Dst: dst, DstPort: e.DstPort,
				Protocol: e.Protocol, Path: e.Path,
				FirstSeen: e.FirstSeen, LastSeen: e.LastSeen,
			}
			svcEdges[id] = se
		}
		se.Connections += e.Connections
		se.ActiveConns += e.ActiveConns
		se.SeededConns += e.SeededConns
		se.BytesSent += e.BytesSent
		se.BytesRecv += e.BytesRecv
		se.Failures += e.Failures
		se.Resets += e.Resets
		se.Retransmits += e.Retransmits
		if e.LastRTTUs > se.LastRTTUs {
			se.LastRTTUs = e.LastRTTUs
		}
		if e.FirstSeen.Before(se.FirstSeen) {
			se.FirstSeen = e.FirstSeen
		}
		if e.LastSeen.After(se.LastSeen) {
			se.LastSeen = e.LastSeen
		}
		if e.Window != nil {
			if se.Window == nil {
				w := *e.Window
				se.Window = &w
			} else {
				mergeWindow(se.Window, e.Window)
			}
		}
		se.RawEdges = append(se.RawEdges, e.ID)
	}

	out := Graph{GeneratedAt: snap.GeneratedAt}
	for _, svc := range svcNodes {
		slices.Sort(svc.Members)
		svc.MemberCount = len(svc.Members)
		slices.Sort(svc.ListenPorts)
		out.Nodes = append(out.Nodes, *svc)
	}
	for _, se := range svcEdges {
		slices.Sort(se.RawEdges)
		out.Edges = append(out.Edges, *se)
	}
	slices.SortFunc(out.Nodes, func(a, b Node) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(out.Edges, func(a, b Edge) int { return strings.Compare(a.ID, b.ID) })
	return out
}

func classify(n *graph.Node, opts Options) (id, label, kind string, category Category) {
	if n.Kind == graph.NodeContainer {
		if n.ComposeProject != "" && n.ComposeService != "" {
			return "svc:compose:" + n.ComposeProject + "/" + n.ComposeService,
				n.ComposeService, "compose", CategoryApp
		}
		label := n.ContainerName
		if label == "" {
			label = n.Label
		}
		return "svc:container:" + n.ID, label, "container", CategoryApp
	}

	base := path.Base(n.Exe)
	if base == "." || base == "/" || base == "" {
		base = n.Label
	}
	id = "svc:proc:" + base
	category = CategoryApp
	switch {
	case opts.SelfExe != "" && n.Exe == opts.SelfExe:
		category = CategoryAtlas
	case systemExes[base]:
		category = CategorySystem
	}
	return id, base, "process", category
}

func mergeWindow(dst, src *graph.EdgeWindow) {
	// Weighted RTT merge before the counters change.
	totalCount := uint64(0)
	sum := uint64(0)
	for _, w := range []*graph.EdgeWindow{dst, src} {
		// Approximate each window's sample count by closes + opens; the
		// avg carries its own weight only via rtt-bearing closes, so use
		// the average as-is weighted by 1 when present.
		if w.RTTAvgUs > 0 {
			totalCount++
			sum += uint64(w.RTTAvgUs)
		}
	}
	if totalCount > 0 {
		dst.RTTAvgUs = uint32(sum / totalCount)
	}
	if src.RTTMaxUs > dst.RTTMaxUs {
		dst.RTTMaxUs = src.RTTMaxUs
	}
	dst.Opens += src.Opens
	dst.Closes += src.Closes
	dst.Failures += src.Failures
	dst.Resets += src.Resets
	dst.Retransmits += src.Retransmits
	dst.BytesSent += src.BytesSent
	dst.BytesRecv += src.BytesRecv
	dst.ActiveEnd += src.ActiveEnd
}

// MemberIndex maps every raw member node id to its service id.
func (g Graph) MemberIndex() map[string]string {
	out := make(map[string]string)
	for _, n := range g.Nodes {
		for _, m := range n.Members {
			out[m] = n.ID
		}
	}
	return out
}

// LabelIndex maps service ids to display labels.
func (g Graph) LabelIndex() map[string]string {
	out := make(map[string]string, len(g.Nodes))
	for _, n := range g.Nodes {
		out[n.ID] = n.Label
	}
	return out
}

// mergeMetrics folds one member's resources into a service aggregate:
// deltas and sizes sum, PSI keeps the worst member, the window length is
// shared.
func mergeMetrics(dst, src *graph.NodeMetrics) *graph.NodeMetrics {
	if dst == nil {
		c := *src
		return &c
	}
	dst.CPUMillis += src.CPUMillis
	dst.RSSBytes += src.RSSBytes
	dst.IOReadBytes += src.IOReadBytes
	dst.IOWriteBytes += src.IOWriteBytes
	dst.FDs += src.FDs
	dst.Threads += src.Threads
	dst.Procs += src.Procs
	dst.ThrottledUs += src.ThrottledUs
	dst.OOMKills += src.OOMKills
	dst.MemLimit += src.MemLimit
	if src.PSICpuSomePct > dst.PSICpuSomePct {
		dst.PSICpuSomePct = src.PSICpuSomePct
	}
	if src.PSIMemSomePct > dst.PSIMemSomePct {
		dst.PSIMemSomePct = src.PSIMemSomePct
	}
	if src.WindowSecs > dst.WindowSecs {
		dst.WindowSecs = src.WindowSecs
	}
	return dst
}

func portString(p uint16) string {
	if p == 0 {
		return "0"
	}
	var buf [5]byte
	i := len(buf)
	for p > 0 {
		i--
		buf[i] = byte('0' + p%10)
		p /= 10
	}
	return string(buf[i:])
}

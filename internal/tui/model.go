// Package tui is `atlas top`: a terminal client over the same HTTP API
// the web UI uses. It holds no collection logic of its own — every
// number comes from the agent's /api/appview, /api/meta and
// /api/lifecycle responses.
package tui

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

// ---- API mirror types (the JSON the agent serves) ----

type NodeMetrics struct {
	WindowSecs   int     `json:"windowSecs"`
	CPUMillis    uint64  `json:"cpuMillis"`
	RSSBytes     uint64  `json:"rssBytes"`
	IOReadBytes  uint64  `json:"ioReadBytes"`
	IOWriteBytes uint64  `json:"ioWriteBytes"`
	FDs          int     `json:"fds"`
	Threads      int     `json:"threads"`
	Procs        int     `json:"procs"`
	ThrottledUs  uint64  `json:"throttledUs"`
	OOMKills     uint64  `json:"oomKills"`
	MemLimit     uint64  `json:"memLimit"`
	PSICpu       float64 `json:"psiCpuSomePct"`
	PSIMem       float64 `json:"psiMemSomePct"`
}

type EdgeWindow struct {
	Seconds     int    `json:"seconds"`
	Opens       uint64 `json:"opens"`
	Failures    uint64 `json:"failures"`
	Resets      uint64 `json:"resets"`
	Retransmits uint64 `json:"retransmits"`
	RTTAvgUs    uint32 `json:"rttAvgUs"`
}

type AppNode struct {
	ID          string       `json:"id"`
	Label       string       `json:"label"`
	Category    string       `json:"category"`
	Kind        string       `json:"kind"`
	Members     []string     `json:"members"`
	MemberCount int          `json:"memberCount"`
	ListenPorts []uint16     `json:"listenPorts"`
	Metrics     *NodeMetrics `json:"metrics"`
}

type AppEdge struct {
	ID          string      `json:"id"`
	Src         string      `json:"src"`
	Dst         string      `json:"dst"`
	DstPort     uint16      `json:"dstPort"`
	Protocol    string      `json:"protocol"`
	Path        string      `json:"path"`
	Connections uint64      `json:"connections"`
	ActiveConns int64       `json:"activeConns"`
	Failures    uint64      `json:"failures"`
	LastRTTUs   uint32      `json:"lastRttUs"`
	Window      *EdgeWindow `json:"window"`
}

type AppGraph struct {
	Nodes []AppNode `json:"nodes"`
	Edges []AppEdge `json:"edges"`
}

type Meta struct {
	Version string `json:"version"`
	Kernel  string `json:"kernel"`
	HostPSI *struct {
		CPUSomePct float64 `json:"cpuSomePct"`
		MemSomePct float64 `json:"memSomePct"`
		IOSomePct  float64 `json:"ioSomePct"`
		Available  bool    `json:"available"`
	} `json:"hostPsi"`
	Collector struct {
		Events       uint64 `json:"events"`
		FailedConns  uint64 `json:"failedConns"`
		UnixConnects uint64 `json:"unixConnects"`
	} `json:"collector"`
	KernelDrops uint64 `json:"kernelDrops"`
}

type LifeEvent struct {
	NodeID string    `json:"node"`
	Kind   string    `json:"kind"`
	Detail string    `json:"detail"`
	Time   time.Time `json:"time"`
}

// Client fetches the agent's API.
type Client struct {
	BaseURL string
	HTTP    *http.Client
}

func (c *Client) get(path string, out any) error {
	resp, err := c.HTTP.Get(c.BaseURL + path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: HTTP %d", path, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// Snapshot is everything one refresh needs.
type Snapshot struct {
	Graph AppGraph
	Meta  Meta
	Life  []LifeEvent
}

func (c *Client) Fetch() (Snapshot, error) {
	var s Snapshot
	if err := c.get("/api/appview", &s.Graph); err != nil {
		return s, err
	}
	if err := c.get("/api/meta", &s.Meta); err != nil {
		return s, err
	}
	var life struct {
		Events []LifeEvent `json:"events"`
	}
	if err := c.get("/api/lifecycle", &life); err == nil {
		s.Life = life.Events
	}
	return s, nil
}

// ---- view model ----

// Row is one service line in the table.
type Row struct {
	ID       string
	Label    string
	Kind     string
	Category string
	CPUPct   float64
	RSS      uint64
	Active   int64
	Rate     uint64 // opens across the window on all touching edges
	Fails    uint64
	RTTUs    uint32 // worst outgoing avg
	OOMs     uint64
	Deps     int
	Callers  int
}

type SortKey string

const (
	SortCPU  SortKey = "cpu"
	SortRSS  SortKey = "rss"
	SortConn SortKey = "conns"
	SortFail SortKey = "fails"
	SortName SortKey = "name"
)

var sortOrder = []SortKey{SortCPU, SortRSS, SortConn, SortFail, SortName}

// NextSort cycles the sort key.
func NextSort(k SortKey) SortKey {
	for i, s := range sortOrder {
		if s == k {
			return sortOrder[(i+1)%len(sortOrder)]
		}
	}
	return SortCPU
}

// BuildRows derives the table from the service graph. System/atlas
// services are hidden unless showSystem; the external aggregate is
// always excluded (it is an endpoint bucket, not a service).
func BuildRows(g AppGraph, filter string, showSystem bool, focus string) []Row {
	visible := func(n AppNode) bool {
		if n.Category == "external" {
			return false
		}
		if !showSystem && (n.Category == "system" || n.Category == "atlas") {
			return false
		}
		return true
	}

	var closure map[string]bool
	if focus != "" {
		closure = focusClosure(g, focus)
	}

	q := strings.ToLower(strings.TrimSpace(filter))
	var rows []Row
	for _, n := range g.Nodes {
		if !visible(n) {
			continue
		}
		if closure != nil && !closure[n.ID] {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(n.Label), q) &&
			!strings.Contains(strings.ToLower(n.ID), q) {
			continue
		}
		r := Row{ID: n.ID, Label: n.Label, Kind: n.Kind, Category: n.Category}
		if m := n.Metrics; m != nil && m.WindowSecs > 0 {
			r.CPUPct = float64(m.CPUMillis) / 1000 / float64(m.WindowSecs) * 100
			r.RSS = m.RSSBytes
			r.OOMs = m.OOMKills
		}
		for _, e := range g.Edges {
			touches := e.Src == n.ID || e.Dst == n.ID
			if !touches {
				continue
			}
			r.Active += e.ActiveConns
			if e.Window != nil {
				r.Rate += e.Window.Opens
				r.Fails += e.Window.Failures
			} else {
				r.Fails += e.Failures
			}
			if e.Src == n.ID {
				r.Deps++
				rtt := e.LastRTTUs
				if e.Window != nil && e.Window.RTTAvgUs > 0 {
					rtt = e.Window.RTTAvgUs
				}
				if rtt > r.RTTUs {
					r.RTTUs = rtt
				}
			} else {
				r.Callers++
			}
		}
		rows = append(rows, r)
	}
	return rows
}

// SortRows orders rows by the key (desc for numeric, asc for name),
// with the name as tiebreak so the order is deterministic.
func SortRows(rows []Row, key SortKey) {
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		switch key {
		case SortRSS:
			if a.RSS != b.RSS {
				return a.RSS > b.RSS
			}
		case SortConn:
			if a.Active != b.Active {
				return a.Active > b.Active
			}
		case SortFail:
			if a.Fails != b.Fails {
				return a.Fails > b.Fails
			}
		case SortName:
			return a.Label < b.Label
		default: // cpu
			if a.CPUPct != b.CPUPct {
				return a.CPUPct > b.CPUPct
			}
		}
		return a.Label < b.Label
	})
}

// focusClosure is the upstream+downstream closure of a service —
// the same semantics as the web UI's Focus.
func focusClosure(g AppGraph, id string) map[string]bool {
	out := make(map[string][]string)
	in := make(map[string][]string)
	for _, e := range g.Edges {
		out[e.Src] = append(out[e.Src], e.Dst)
		in[e.Dst] = append(in[e.Dst], e.Src)
	}
	seen := map[string]bool{id: true}
	walk := func(adj map[string][]string) {
		queue := []string{id}
		local := map[string]bool{id: true}
		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			for _, next := range adj[cur] {
				if !local[next] {
					local[next] = true
					seen[next] = true
					queue = append(queue, next)
				}
			}
		}
	}
	walk(out)
	walk(in)
	return seen
}

// Package graph maintains the service dependency graph derived from
// observed connections. It is the single source of truth the API serves.
package graph

import (
	"slices"
	"sync"
	"time"
)

// NodeKind classifies graph nodes.
type NodeKind string

const (
	// NodeProcess is a host process (or group of processes sharing an
	// executable).
	NodeProcess NodeKind = "process"
	// NodeContainer is a Docker/OCI container.
	NodeContainer NodeKind = "container"
	// NodeExternal is a remote endpoint Atlas cannot attribute to a
	// local process (off-host peer).
	NodeExternal NodeKind = "external"
)

// NodeSpec is the identity a caller provides when reporting an
// observation. The store merges specs into persistent nodes.
type NodeSpec struct {
	ID          string
	Kind        NodeKind
	Label       string
	Exe         string
	ContainerID string
	PID         uint32 // 0 = not applicable
	Addr        string // observed address for this endpoint, "" if unknown
}

// Node is a service in the graph.
type Node struct {
	ID            string    `json:"id"`
	Kind          NodeKind  `json:"kind"`
	Label         string    `json:"label"`
	Exe           string    `json:"exe,omitempty"`
	ContainerID   string    `json:"containerId,omitempty"`
	ContainerName string    `json:"containerName,omitempty"`
	Image         string    `json:"image,omitempty"`
	PIDs          []uint32  `json:"pids,omitempty"`
	ListenPorts   []uint16  `json:"listenPorts,omitempty"`
	Addrs         []string  `json:"addrs,omitempty"`
	FirstSeen     time.Time `json:"firstSeen"`
	LastSeen      time.Time `json:"lastSeen"`
}

// Edge is observed communication between two nodes towards one server
// port.
type Edge struct {
	ID          string    `json:"id"`
	Src         string    `json:"src"`
	Dst         string    `json:"dst"`
	DstPort     uint16    `json:"dstPort"`
	Protocol    string    `json:"protocol"`
	Connections uint64    `json:"connections"`
	ActiveConns int64     `json:"activeConns"`
	BytesSent   uint64    `json:"bytesSent"`
	BytesRecv   uint64    `json:"bytesRecv"`
	FirstSeen   time.Time `json:"firstSeen"`
	LastSeen    time.Time `json:"lastSeen"`
}

// Snapshot is a consistent copy of the graph.
type Snapshot struct {
	Version     uint64    `json:"version"`
	GeneratedAt time.Time `json:"generatedAt"`
	Nodes       []Node    `json:"nodes"`
	Edges       []Edge    `json:"edges"`
}

// Store is a mutex-guarded in-memory graph with change notification.
type Store struct {
	mu      sync.Mutex
	nodes   map[string]*Node
	edges   map[string]*Edge
	version uint64
	subs    map[chan struct{}]struct{}
}

func NewStore() *Store {
	return &Store{
		nodes: make(map[string]*Node),
		edges: make(map[string]*Edge),
		subs:  make(map[chan struct{}]struct{}),
	}
}

// EdgeID derives the stable edge identity used by ObserveConnection.
func EdgeID(srcID, dstID string, dstPort uint16) string {
	return srcID + "->" + dstID + ":" + itoa(dstPort)
}

func itoa(p uint16) string {
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

// ObserveConnection records one established connection from src to dst on
// dstPort and returns the edge id for later ConnectionClosed calls.
func (s *Store) ObserveConnection(src, dst NodeSpec, dstPort uint16, at time.Time) string {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.upsertNodeLocked(src, at)
	s.upsertNodeLocked(dst, at)

	id := EdgeID(src.ID, dst.ID, dstPort)
	e, ok := s.edges[id]
	if !ok {
		e = &Edge{
			ID:        id,
			Src:       src.ID,
			Dst:       dst.ID,
			DstPort:   dstPort,
			Protocol:  "tcp",
			FirstSeen: at,
		}
		s.edges[id] = e
	}
	e.Connections++
	e.ActiveConns++
	if at.After(e.LastSeen) {
		e.LastSeen = at
	}
	s.bumpLocked()
	return id
}

// ConnectionClosed folds a finished connection into its edge aggregate.
// countBytes reports whether the byte counters should be added (the
// caller accounts each logical connection's bytes exactly once).
func (s *Store) ConnectionClosed(edgeID string, bytesSent, bytesRecv uint64, at time.Time, countBytes bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.edges[edgeID]
	if !ok {
		return
	}
	if e.ActiveConns > 0 {
		e.ActiveConns--
	}
	if countBytes {
		e.BytesSent += bytesSent
		e.BytesRecv += bytesRecv
	}
	if at.After(e.LastSeen) {
		e.LastSeen = at
	}
	s.bumpLocked()
}

// ObserveListen records that the node identified by spec listens on port.
func (s *Store) ObserveListen(spec NodeSpec, port uint16, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	n := s.upsertNodeLocked(spec, at)
	if !slices.Contains(n.ListenPorts, port) {
		n.ListenPorts = append(n.ListenPorts, port)
		slices.Sort(n.ListenPorts)
		s.bumpLocked()
	}
}

// SetContainerMeta attaches a resolved container name/image to a node.
func (s *Store) SetContainerMeta(nodeID, name, image string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	n, ok := s.nodes[nodeID]
	if !ok {
		return
	}
	changed := false
	if name != "" && n.ContainerName != name {
		n.ContainerName = name
		n.Label = name
		changed = true
	}
	if image != "" && n.Image != image {
		n.Image = image
		changed = true
	}
	if changed {
		s.bumpLocked()
	}
}

func (s *Store) upsertNodeLocked(spec NodeSpec, at time.Time) *Node {
	n, ok := s.nodes[spec.ID]
	if !ok {
		n = &Node{
			ID:          spec.ID,
			Kind:        spec.Kind,
			Label:       spec.Label,
			Exe:         spec.Exe,
			ContainerID: spec.ContainerID,
			FirstSeen:   at,
		}
		s.nodes[spec.ID] = n
	}
	if at.After(n.LastSeen) {
		n.LastSeen = at
	}
	// A container node may first appear with only a short-id label;
	// don't overwrite a resolved container name with one.
	if n.ContainerName == "" && spec.Label != "" && n.Label == "" {
		n.Label = spec.Label
	}
	if n.Exe == "" && spec.Exe != "" {
		n.Exe = spec.Exe
	}
	if spec.PID != 0 && !slices.Contains(n.PIDs, spec.PID) {
		n.PIDs = append(n.PIDs, spec.PID)
		slices.Sort(n.PIDs)
	}
	if spec.Addr != "" && !slices.Contains(n.Addrs, spec.Addr) {
		n.Addrs = append(n.Addrs, spec.Addr)
		slices.Sort(n.Addrs)
	}
	return n
}

func (s *Store) bumpLocked() {
	s.version++
	for ch := range s.subs {
		select {
		case ch <- struct{}{}:
		default: // subscriber already has a pending notification
		}
	}
}

// Subscribe returns a channel that receives a (coalesced) signal whenever
// the graph changes, plus a cancel func.
func (s *Store) Subscribe() (<-chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	s.mu.Lock()
	s.subs[ch] = struct{}{}
	s.mu.Unlock()
	return ch, func() {
		s.mu.Lock()
		delete(s.subs, ch)
		s.mu.Unlock()
	}
}

// Version returns the current change counter.
func (s *Store) Version() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.version
}

// Snapshot returns a deep copy ordered deterministically.
func (s *Store) Snapshot() Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()

	snap := Snapshot{
		Version:     s.version,
		GeneratedAt: time.Now().UTC(),
		Nodes:       make([]Node, 0, len(s.nodes)),
		Edges:       make([]Edge, 0, len(s.edges)),
	}
	for _, n := range s.nodes {
		c := *n
		c.PIDs = slices.Clone(n.PIDs)
		c.ListenPorts = slices.Clone(n.ListenPorts)
		c.Addrs = slices.Clone(n.Addrs)
		snap.Nodes = append(snap.Nodes, c)
	}
	for _, e := range s.edges {
		snap.Edges = append(snap.Edges, *e)
	}
	slices.SortFunc(snap.Nodes, func(a, b Node) int {
		return compareStrings(a.ID, b.ID)
	})
	slices.SortFunc(snap.Edges, func(a, b Edge) int {
		return compareStrings(a.ID, b.ID)
	})
	return snap
}

func compareStrings(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

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
	ID             string    `json:"id"`
	Kind           NodeKind  `json:"kind"`
	Label          string    `json:"label"`
	Exe            string    `json:"exe,omitempty"`
	ContainerID    string    `json:"containerId,omitempty"`
	ContainerName  string    `json:"containerName,omitempty"`
	Image          string    `json:"image,omitempty"`
	ComposeProject string    `json:"composeProject,omitempty"`
	ComposeService string    `json:"composeService,omitempty"`
	PIDs           []uint32  `json:"pids,omitempty"`
	ListenPorts    []uint16  `json:"listenPorts,omitempty"`
	Addrs          []string  `json:"addrs,omitempty"`
	FirstSeen      time.Time `json:"firstSeen"`
	LastSeen       time.Time `json:"lastSeen"`
	// Metrics is the latest resource sample window (live view) or the
	// reconstructed window (replay); nil when never sampled.
	Metrics *NodeMetrics `json:"metrics,omitempty"`
}

// NodeMetrics is one resource window for a node, sampled from
// procfs/cgroupfs.
type NodeMetrics struct {
	WindowSecs   int    `json:"windowSecs"`
	CPUMillis    uint64 `json:"cpuMillis"` // CPU time consumed in the window
	RSSBytes     uint64 `json:"rssBytes"`  // gauge (max within the window)
	IOReadBytes  uint64 `json:"ioReadBytes"`
	IOWriteBytes uint64 `json:"ioWriteBytes"`
	FDs          int    `json:"fds"`
	Threads      int    `json:"threads"`
	Procs        int    `json:"procs"`
	ThrottledUs  uint64 `json:"throttledUs"` // cgroup CPU throttling in the window
	OOMKills     uint64 `json:"oomKills"`    // cgroup memory.events oom_kill delta
	MemLimit     uint64 `json:"memLimit"`    // cgroup memory.max, 0 = none
	// PSI some-avg10 percentages from the node's cgroup, when the
	// kernel exposes them; 0 when unavailable.
	PSICpuSomePct float64 `json:"psiCpuSomePct,omitempty"`
	PSIMemSomePct float64 `json:"psiMemSomePct,omitempty"`
}

// Edge is observed communication between two nodes towards one server
// port.
type Edge struct {
	ID       string `json:"id"`
	Src      string `json:"src"`
	Dst      string `json:"dst"`
	DstPort  uint16 `json:"dstPort"`
	Protocol string `json:"protocol"`
	// Path is the AF_UNIX socket path for protocol "unix" edges.
	Path        string    `json:"path,omitempty"`
	Connections uint64    `json:"connections"`
	ActiveConns int64     `json:"activeConns"`
	BytesSent   uint64    `json:"bytesSent"`
	BytesRecv   uint64    `json:"bytesRecv"`
	Failures    uint64    `json:"failures,omitempty"`
	Resets      uint64    `json:"resets,omitempty"`
	Retransmits uint64    `json:"retransmits,omitempty"`
	LastRTTUs   uint32    `json:"lastRttUs,omitempty"`
	FirstSeen   time.Time `json:"firstSeen"`
	LastSeen    time.Time `json:"lastSeen"`
	// Window carries recent (live view) or at-that-moment (replay)
	// health aggregates; populated by the API layer, not the store.
	Window *EdgeWindow `json:"window,omitempty"`
}

// EdgeWindow is per-edge health aggregated over a time window.
type EdgeWindow struct {
	Seconds     int    `json:"seconds"`
	Opens       uint64 `json:"opens"`
	Closes      uint64 `json:"closes"`
	Failures    uint64 `json:"failures"`
	Resets      uint64 `json:"resets"`
	Retransmits uint64 `json:"retransmits"`
	BytesSent   uint64 `json:"bytesSent"`
	BytesRecv   uint64 `json:"bytesRecv"`
	RTTAvgUs    uint32 `json:"rttAvgUs"`
	RTTMaxUs    uint32 `json:"rttMaxUs"`
	ActiveEnd   int64  `json:"activeEnd"`
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
	// pending holds container/compose metadata that arrived before its
	// node existed (async enrichment can win that race — a container's
	// exec event enqueues a lookup before its first connection creates
	// the node). Applied and cleared when the node appears.
	pending map[string]*pendingMeta
}

type pendingMeta struct {
	name, image      string
	project, service string
}

// pendingMetaCap bounds the stash; enrichment retries cover eviction.
const pendingMetaCap = 4096

func NewStore() *Store {
	return &Store{
		nodes:   make(map[string]*Node),
		edges:   make(map[string]*Edge),
		subs:    make(map[chan struct{}]struct{}),
		pending: make(map[string]*pendingMeta),
	}
}

// pendingFor returns (creating if needed) the stash entry for a node id.
func (s *Store) pendingFor(nodeID string) *pendingMeta {
	if p, ok := s.pending[nodeID]; ok {
		return p
	}
	if len(s.pending) >= pendingMetaCap {
		for k := range s.pending {
			delete(s.pending, k)
			break
		}
	}
	p := &pendingMeta{}
	s.pending[nodeID] = p
	return p
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

// UnixEdgeID derives the stable id for an AF_UNIX edge.
func UnixEdgeID(srcID, dstID, path string) string {
	return srcID + "->" + dstID + ":unix:" + path
}

// unixEdgeLocked upserts the AF_UNIX edge shell.
func (s *Store) unixEdgeLocked(src, dst NodeSpec, path string, at time.Time) *Edge {
	s.upsertNodeLocked(src, at)
	s.upsertNodeLocked(dst, at)
	id := UnixEdgeID(src.ID, dst.ID, path)
	e, ok := s.edges[id]
	if !ok {
		e = &Edge{
			ID: id, Src: src.ID, Dst: dst.ID,
			Protocol: "unix", Path: path, FirstSeen: at,
		}
		s.edges[id] = e
	}
	if at.After(e.LastSeen) {
		e.LastSeen = at
	}
	return e
}

// UnixConnectObserved counts one successful AF_UNIX connect (exact,
// from kernel events).
func (s *Store) UnixConnectObserved(src, dst NodeSpec, path string, at time.Time) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.unixEdgeLocked(src, dst, path, at)
	e.Connections++
	s.bumpLocked()
	return e.ID
}

// UnixPairUp raises the standing-connection gauge for a pair discovered
// by the socket-table scan (sampled evidence).
func (s *Store) UnixPairUp(src, dst NodeSpec, path string, at time.Time) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.unixEdgeLocked(src, dst, path, at)
	e.ActiveConns++
	s.bumpLocked()
	return e.ID
}

// UnixPairDown releases a standing pair that vanished from the scan.
func (s *Store) UnixPairDown(edgeID string, at time.Time) {
	s.edgeCounter(edgeID, at, func(e *Edge) {
		if e.ActiveConns > 0 {
			e.ActiveConns--
		}
	})
}

// ObserveUnixFailure records a refused/failed AF_UNIX connect towards
// path on the dst node.
func (s *Store) ObserveUnixFailure(src, dst NodeSpec, path string, at time.Time) string {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.upsertNodeLocked(src, at)
	s.upsertNodeLocked(dst, at)

	id := UnixEdgeID(src.ID, dst.ID, path)
	e, ok := s.edges[id]
	if !ok {
		e = &Edge{
			ID: id, Src: src.ID, Dst: dst.ID,
			Protocol: "unix", Path: path, FirstSeen: at,
		}
		s.edges[id] = e
	}
	e.Failures++
	if at.After(e.LastSeen) {
		e.LastSeen = at
	}
	s.bumpLocked()
	return id
}

// HasNode reports whether a node id currently exists.
func (s *Store) HasNode(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.nodes[id]
	return ok
}

// SetNodeMetrics attaches the latest resource sample to a node.
func (s *Store) SetNodeMetrics(nodeID string, m NodeMetrics) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := s.nodes[nodeID]
	if !ok {
		return
	}
	c := m
	n.Metrics = &c
	s.bumpLocked()
}

// ObserveFailure records a failed connection attempt from src towards
// dst on dstPort. The edge is created if absent; failed attempts never
// count as connections.
func (s *Store) ObserveFailure(src, dst NodeSpec, dstPort uint16, at time.Time) string {
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
	e.Failures++
	if at.After(e.LastSeen) {
		e.LastSeen = at
	}
	s.bumpLocked()
	return id
}

// EdgeResets counts n received RSTs on the edge.
func (s *Store) EdgeResets(edgeID string, n uint64, at time.Time) {
	if n == 0 {
		return
	}
	s.edgeCounter(edgeID, at, func(e *Edge) { e.Resets += n })
}

// EdgeRetrans counts n retransmitted segments on the edge.
func (s *Store) EdgeRetrans(edgeID string, n uint64, at time.Time) {
	if n == 0 {
		return
	}
	s.edgeCounter(edgeID, at, func(e *Edge) { e.Retransmits += n })
}

// EdgeRTTSample records the latest smoothed RTT observed on the edge.
func (s *Store) EdgeRTTSample(edgeID string, rttUs uint32, at time.Time) {
	if rttUs == 0 {
		return
	}
	s.edgeCounter(edgeID, at, func(e *Edge) { e.LastRTTUs = rttUs })
}

func (s *Store) edgeCounter(edgeID string, at time.Time, apply func(*Edge)) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.edges[edgeID]
	if !ok {
		return
	}
	apply(e)
	if at.After(e.LastSeen) {
		e.LastSeen = at
	}
	s.bumpLocked()
}

// SetComposeIdentity attaches docker-compose project/service labels to a
// node. Labels arriving before the node exists are stashed and applied
// when it appears.
func (s *Store) SetComposeIdentity(nodeID, project, service string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	n, ok := s.nodes[nodeID]
	if !ok {
		p := s.pendingFor(nodeID)
		p.project, p.service = project, service
		return
	}
	if n.ComposeProject == project && n.ComposeService == service {
		return
	}
	n.ComposeProject = project
	n.ComposeService = service
	s.bumpLocked()
}

// UpsertNode ensures a node exists with the given identity. Used for
// listeners observed outside any connection — e.g. an AF_UNIX server
// that never speaks TCP would otherwise exist only as a bare id.
func (s *Store) UpsertNode(spec NodeSpec, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, existed := s.nodes[spec.ID]
	var pids, addrs int
	var exe string
	if existed {
		pids, addrs, exe = len(prev.PIDs), len(prev.Addrs), prev.Exe
	}
	n := s.upsertNodeLocked(spec, at)
	if !existed || len(n.PIDs) != pids || len(n.Addrs) != addrs || n.Exe != exe {
		s.bumpLocked()
	}
}

// ListenerSet is one node's complete set of listening ports as observed
// by a scan.
type ListenerSet struct {
	Spec  NodeSpec
	Ports []uint16
}

// SyncListeners replaces listening-port state from a full scan: nodes in
// sets get exactly those ports (and are created if unknown); nodes not
// mentioned lose their ports. This keeps "listening" truthful — a
// stopped service stops showing its old ports.
func (s *Store) SyncListeners(sets []ListenerSet, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	changed := false
	seen := make(map[string]struct{}, len(sets))
	for _, ls := range sets {
		seen[ls.Spec.ID] = struct{}{}
		n := s.upsertNodeLocked(ls.Spec, at)
		ports := slices.Clone(ls.Ports)
		slices.Sort(ports)
		ports = slices.Compact(ports)
		if !slices.Equal(n.ListenPorts, ports) {
			n.ListenPorts = ports
			changed = true
		}
	}
	for id, n := range s.nodes {
		if _, ok := seen[id]; !ok && len(n.ListenPorts) > 0 {
			n.ListenPorts = nil
			changed = true
		}
	}
	if changed {
		s.bumpLocked()
	}
}

// SetContainerMeta attaches a resolved container name/image to a node.
// Metadata arriving before the node exists is stashed and applied when
// it appears.
func (s *Store) SetContainerMeta(nodeID, name, image string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	n, ok := s.nodes[nodeID]
	if !ok {
		p := s.pendingFor(nodeID)
		p.name, p.image = name, image
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
		if p, held := s.pending[spec.ID]; held {
			delete(s.pending, spec.ID)
			if p.name != "" {
				n.ContainerName = p.name
				n.Label = p.name
			}
			if p.image != "" {
				n.Image = p.image
			}
			n.ComposeProject = p.project
			n.ComposeService = p.service
		}
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
		if n.Metrics != nil {
			m := *n.Metrics
			c.Metrics = &m
		}
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

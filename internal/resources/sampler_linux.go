//go:build linux

package resources

import (
	"bytes"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sikurdev/sikur-atlas/internal/graph"
	"github.com/sikurdev/sikur-atlas/internal/procfs"
)

// userHZ is the kernel's clock tick for /proc/<pid>/stat times; 100 on
// every mainstream architecture/config.
const userHZ = 100

// MetricsSink receives per-node samples (implemented by history.Store).
type MetricsSink interface {
	NodeSample(nodeID string, m graph.NodeMetrics, at time.Time)
}

// HostPSI is the host-level pressure snapshot for /api/meta.
type HostPSI struct {
	CPUSomePct float64 `json:"cpuSomePct"`
	MemSomePct float64 `json:"memSomePct"`
	IOSomePct  float64 `json:"ioSomePct"`
	Available  bool    `json:"available"`
}

type prevTotals struct {
	cpuMillis   uint64
	ioRead      uint64
	ioWrite     uint64
	throttledUs uint64
	oomKills    uint64
	valid       bool
}

// Sampler collects one resource window per node per interval, bounded
// by the topology size (only container/process nodes with known pids).
//
// Attribution is re-verified on every pass: a recorded pid only
// contributes if /proc still shows it belonging to this node (same
// container cgroup, same executable). The kernel recycles pids, and a
// recycled pid would otherwise silently attribute a foreign process's
// — or a foreign cgroup's — resources to the node, forever, into
// history. Verified-stale pids are pruned from the graph node.
type Sampler struct {
	store *graph.Store
	sink  MetricsSink

	// procRoot/cgroupRoot exist so tests can point the sampler at a
	// fake tree; production always uses the real mounts.
	procRoot   string
	cgroupRoot string

	mu      sync.Mutex
	prev    map[string]prevTotals
	lastAt  time.Time
	hostPSI HostPSI
}

func NewSampler(store *graph.Store, sink MetricsSink) *Sampler {
	return &Sampler{
		store:      store,
		sink:       sink,
		procRoot:   "/proc",
		cgroupRoot: "/sys/fs/cgroup",
		prev:       make(map[string]prevTotals),
	}
}

// HostPressure returns the latest host PSI reading.
func (sm *Sampler) HostPressure() HostPSI {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	return sm.hostPSI
}

func (sm *Sampler) procPath(pid uint32, part string) string {
	p := sm.procRoot + "/" + strconv.FormatUint(uint64(pid), 10)
	if part != "" {
		p += "/" + part
	}
	return p
}

// Sample takes one pass over the current topology. The first pass per
// node only establishes baselines (deltas need two points).
func (sm *Sampler) Sample(at time.Time) {
	snap := sm.store.Snapshot()
	pageSize := uint64(os.Getpagesize())

	// The delta window is the real gap since the previous pass; a
	// node's baseline is at most one pass old (newer ones are skipped).
	sm.mu.Lock()
	last := sm.lastAt
	sm.lastAt = at
	sm.mu.Unlock()
	windowSecs := 0
	if !last.IsZero() {
		windowSecs = int(at.Sub(last).Round(time.Second) / time.Second)
	}

	sampled := make(map[string]bool, len(snap.Nodes))
	for i := range snap.Nodes {
		n := &snap.Nodes[i]
		if n.Kind == graph.NodeExternal || len(n.PIDs) == 0 {
			continue
		}
		var m graph.NodeMetrics
		var totals prevTotals
		var stale []uint32
		if n.Kind == graph.NodeContainer {
			totals, stale = sm.sampleCgroup(n, pageSize, &m)
		} else {
			totals, stale = sm.sampleProcs(n, pageSize, &m)
		}
		if len(stale) > 0 {
			sm.store.RemoveNodePIDs(n.ID, stale)
		}
		if !totals.valid {
			continue
		}
		sampled[n.ID] = true

		sm.mu.Lock()
		prev, had := sm.prev[n.ID]
		sm.prev[n.ID] = totals
		sm.mu.Unlock()
		if !had || !prev.valid || windowSecs <= 0 {
			continue // baseline only
		}
		m.WindowSecs = windowSecs
		m.CPUMillis = sub(totals.cpuMillis, prev.cpuMillis)
		m.IOReadBytes = sub(totals.ioRead, prev.ioRead)
		m.IOWriteBytes = sub(totals.ioWrite, prev.ioWrite)
		m.ThrottledUs = sub(totals.throttledUs, prev.throttledUs)
		m.OOMKills = sub(totals.oomKills, prev.oomKills)

		sm.store.SetNodeMetrics(n.ID, m)
		if sm.sink != nil {
			sm.sink.NodeSample(n.ID, m, at)
		}
	}

	psi := HostPSI{}
	if b, err := os.ReadFile(sm.procRoot + "/pressure/cpu"); err == nil {
		psi.CPUSomePct = ParsePSISome(string(b))
		psi.Available = true
	}
	if b, err := os.ReadFile(sm.procRoot + "/pressure/memory"); err == nil {
		psi.MemSomePct = ParsePSISome(string(b))
	}
	if b, err := os.ReadFile(sm.procRoot + "/pressure/io"); err == nil {
		psi.IOSomePct = ParsePSISome(string(b))
	}
	sm.mu.Lock()
	sm.hostPSI = psi
	// Nodes that produced nothing this pass (vanished container, all
	// pids pruned) lose their baseline: keeping it would leak memory
	// per container ever seen, and a node that comes back deserves a
	// fresh baseline anyway.
	for id := range sm.prev {
		if !sampled[id] {
			delete(sm.prev, id)
		}
	}
	sm.mu.Unlock()
}

// Run samples on the given cadence until ctx is done.
func (sm *Sampler) Run(done <-chan struct{}, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	sm.Sample(time.Now()) // establish baselines immediately
	for {
		select {
		case <-done:
			return
		case now := <-t.C:
			sm.Sample(now)
		}
	}
}

func sub(cur, prev uint64) uint64 {
	if cur < prev {
		return 0 // counter reset (restart, pid churn)
	}
	return cur - prev
}

// sampleCgroup reads a container's cgroup v2 controllers via a member
// pid's cgroup path — but only a pid whose cgroup still names this
// container counts as a member; anything else is reported stale.
func (sm *Sampler) sampleCgroup(n *graph.Node, pageSize uint64, m *graph.NodeMetrics) (prevTotals, []uint32) {
	var live []uint32
	var stale []uint32
	var cgPath string
	for _, pid := range n.PIDs {
		b, err := os.ReadFile(sm.procPath(pid, "cgroup"))
		if err != nil {
			stale = append(stale, pid) // exited
			continue
		}
		if procfs.ParseCgroupContainerID(bytes.NewReader(b)) != n.ContainerID {
			stale = append(stale, pid) // recycled for something else
			continue
		}
		live = append(live, pid)
		if cgPath == "" {
			if p := ParseCgroupV2Path(string(b)); p != "" {
				cgPath = sm.cgroupRoot + p
			}
		}
	}
	if cgPath == "" {
		// cgroup v1, or no verified member left: per-pid sums over the
		// verified members only.
		return sm.sumProcs(live, pageSize, m), stale
	}
	read := func(name string) (string, bool) {
		b, err := os.ReadFile(cgPath + "/" + name)
		if err != nil {
			return "", false
		}
		return string(b), true
	}

	var t prevTotals
	if c, ok := read("cpu.stat"); ok {
		kv := ParseKeyedFile(c)
		t.cpuMillis = kv["usage_usec"] / 1000
		t.throttledUs = kv["throttled_usec"]
		t.valid = true
	}
	if c, ok := read("memory.current"); ok {
		m.RSSBytes = ParseMemMax(c) // same "one integer" format
	}
	if c, ok := read("memory.max"); ok {
		m.MemLimit = ParseMemMax(c)
	}
	if c, ok := read("memory.events"); ok {
		t.oomKills = ParseKeyedFile(c)["oom_kill"]
	}
	if c, ok := read("io.stat"); ok {
		t.ioRead, t.ioWrite = ParseCgroupIOStat(c)
	}
	if c, ok := read("pids.current"); ok {
		m.Procs = int(ParseMemMax(c))
	}
	if c, ok := read("cpu.pressure"); ok {
		m.PSICpuSomePct = ParsePSISome(c)
	}
	if c, ok := read("memory.pressure"); ok {
		m.PSIMemSomePct = ParsePSISome(c)
	}
	m.FDs, m.Threads = sm.sumFDsThreads(live)
	return t, stale
}

// sampleProcs sums per-pid procfs numbers for host process nodes,
// counting only pids that still run the node's executable.
func (sm *Sampler) sampleProcs(n *graph.Node, pageSize uint64, m *graph.NodeMetrics) (prevTotals, []uint32) {
	var live []uint32
	var stale []uint32
	for _, pid := range n.PIDs {
		if n.Exe != "" {
			target, err := os.Readlink(sm.procPath(pid, "exe"))
			if err != nil {
				stale = append(stale, pid) // exited or kernel thread
				continue
			}
			if strings.TrimSuffix(target, " (deleted)") != n.Exe {
				stale = append(stale, pid) // recycled for another program
				continue
			}
		} else if _, err := os.Stat(sm.procPath(pid, "stat")); err != nil {
			stale = append(stale, pid)
			continue
		}
		live = append(live, pid)
	}
	return sm.sumProcs(live, pageSize, m), stale
}

// sumProcs sums /proc numbers over an already-verified pid set.
func (sm *Sampler) sumProcs(pids []uint32, pageSize uint64, m *graph.NodeMetrics) prevTotals {
	var t prevTotals
	for _, pid := range pids {
		stat, err := os.ReadFile(sm.procPath(pid, "stat"))
		if err != nil {
			continue // pid gone since verification
		}
		ticks, threads, ok := ParseProcStat(string(stat))
		if !ok {
			continue
		}
		t.valid = true
		t.cpuMillis += ticks * 1000 / userHZ
		m.Threads += threads
		m.Procs++
		if b, err := os.ReadFile(sm.procPath(pid, "statm")); err == nil {
			m.RSSBytes += ParseStatmRSS(string(b), pageSize)
		}
		if b, err := os.ReadFile(sm.procPath(pid, "io")); err == nil {
			r, w := ParseProcIO(string(b))
			t.ioRead += r
			t.ioWrite += w
		}
		if ents, err := os.ReadDir(sm.procPath(pid, "fd")); err == nil {
			m.FDs += len(ents)
		}
	}
	return t
}

func (sm *Sampler) sumFDsThreads(pids []uint32) (fds, threads int) {
	for _, pid := range pids {
		if ents, err := os.ReadDir(sm.procPath(pid, "fd")); err == nil {
			fds += len(ents)
		}
		if b, err := os.ReadFile(sm.procPath(pid, "stat")); err == nil {
			if _, th, ok := ParseProcStat(string(b)); ok {
				threads += th
			}
		}
	}
	return fds, threads
}

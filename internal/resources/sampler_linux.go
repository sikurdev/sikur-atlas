//go:build linux

package resources

import (
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/sikurdev/sikur-atlas/internal/graph"
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
type Sampler struct {
	store *graph.Store
	sink  MetricsSink

	mu      sync.Mutex
	prev    map[string]prevTotals
	lastAt  time.Time
	hostPSI HostPSI
}

func NewSampler(store *graph.Store, sink MetricsSink) *Sampler {
	return &Sampler{store: store, sink: sink, prev: make(map[string]prevTotals)}
}

// HostPressure returns the latest host PSI reading.
func (sm *Sampler) HostPressure() HostPSI {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	return sm.hostPSI
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

	for i := range snap.Nodes {
		n := &snap.Nodes[i]
		if n.Kind == graph.NodeExternal || len(n.PIDs) == 0 {
			continue
		}
		var m graph.NodeMetrics
		var totals prevTotals
		if n.Kind == graph.NodeContainer {
			totals = sm.sampleCgroup(n, &m)
		} else {
			totals = sm.sampleProcs(n, pageSize, &m)
		}
		if !totals.valid {
			continue
		}

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
	if b, err := os.ReadFile("/proc/pressure/cpu"); err == nil {
		psi.CPUSomePct = ParsePSISome(string(b))
		psi.Available = true
	}
	if b, err := os.ReadFile("/proc/pressure/memory"); err == nil {
		psi.MemSomePct = ParsePSISome(string(b))
	}
	if b, err := os.ReadFile("/proc/pressure/io"); err == nil {
		psi.IOSomePct = ParsePSISome(string(b))
	}
	sm.mu.Lock()
	sm.hostPSI = psi
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

// sampleCgroup reads a container's cgroup v2 controllers via any member
// pid's cgroup path. Gauges land directly in m; monotonic counters go
// into the returned totals for delta computation.
func (sm *Sampler) sampleCgroup(n *graph.Node, m *graph.NodeMetrics) prevTotals {
	var cgPath string
	for _, pid := range n.PIDs {
		b, err := os.ReadFile("/proc/" + strconv.FormatUint(uint64(pid), 10) + "/cgroup")
		if err != nil {
			continue
		}
		if p := ParseCgroupV2Path(string(b)); p != "" {
			cgPath = "/sys/fs/cgroup" + p
			break
		}
	}
	if cgPath == "" {
		// cgroup v1 or vanished pids: fall back to per-pid sums.
		return sm.sampleProcs(n, uint64(os.Getpagesize()), m)
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
	m.FDs, m.Threads = sumFDsThreads(n.PIDs)
	return t
}

// sampleProcs sums per-pid procfs numbers for host process nodes.
func (sm *Sampler) sampleProcs(n *graph.Node, pageSize uint64, m *graph.NodeMetrics) prevTotals {
	var t prevTotals
	for _, pid := range n.PIDs {
		base := "/proc/" + strconv.FormatUint(uint64(pid), 10)
		stat, err := os.ReadFile(base + "/stat")
		if err != nil {
			continue // pid gone
		}
		ticks, threads, ok := ParseProcStat(string(stat))
		if !ok {
			continue
		}
		t.valid = true
		t.cpuMillis += ticks * 1000 / userHZ
		m.Threads += threads
		m.Procs++
		if b, err := os.ReadFile(base + "/statm"); err == nil {
			m.RSSBytes += ParseStatmRSS(string(b), pageSize)
		}
		if b, err := os.ReadFile(base + "/io"); err == nil {
			r, w := ParseProcIO(string(b))
			t.ioRead += r
			t.ioWrite += w
		}
		if ents, err := os.ReadDir(base + "/fd"); err == nil {
			m.FDs += len(ents)
		}
	}
	return t
}

func sumFDsThreads(pids []uint32) (fds, threads int) {
	for _, pid := range pids {
		base := "/proc/" + strconv.FormatUint(uint64(pid), 10)
		if ents, err := os.ReadDir(base + "/fd"); err == nil {
			fds += len(ents)
		}
		if b, err := os.ReadFile(base + "/stat"); err == nil {
			if _, th, ok := ParseProcStat(string(b)); ok {
				threads += th
			}
		}
	}
	return fds, threads
}

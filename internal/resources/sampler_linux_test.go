//go:build linux

package resources

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sikurdev/sikur-atlas/internal/graph"
)

const statLine = "%d (python3) S 1 1 1 0 -1 4194560 2549 0 0 0 37 12 0 0 20 0 2 0 12345 123456789 4321 18446744073709551615 1 1 0 0 0 0 0 0 0 0 0 0 17 3 0 0 0 0 0"

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func fakePid(t *testing.T, procRoot string, pid string, cgroup, exeTarget string) {
	t.Helper()
	base := filepath.Join(procRoot, pid)
	writeFile(t, filepath.Join(base, "cgroup"), cgroup)
	writeFile(t, filepath.Join(base, "stat"), strings.Replace(statLine, "%d", pid, 1))
	writeFile(t, filepath.Join(base, "statm"), "2500 1250 300 50 0 400 0")
	writeFile(t, filepath.Join(base, "io"), "read_bytes: 4096\nwrite_bytes: 8192\n")
	writeFile(t, filepath.Join(base, "fd", ".keep"), "")
	if exeTarget != "" {
		if err := os.Symlink(exeTarget, filepath.Join(base, "exe")); err != nil {
			t.Fatal(err)
		}
	}
}

// A pid the kernel recycled for a foreign process must neither steer
// the container's cgroup resolution nor survive on the node: without
// the identity check, the foreign cgroup's counters would be recorded
// as this container's history.
func TestSampleCgroupRejectsRecycledPid(t *testing.T) {
	dir := t.TempDir()
	procRoot := filepath.Join(dir, "proc")
	cgRoot := filepath.Join(dir, "cgroup")
	cid := strings.Repeat("ab", 32)

	// pid 423: recycled — now a host systemd service.
	fakePid(t, procRoot, "423", "0::/system.slice/ssh.service\n", "")
	// pid 9812: the real container member.
	fakePid(t, procRoot, "9812", "0::/docker/"+cid+"\n", "")
	writeFile(t, filepath.Join(cgRoot, "docker", cid, "cpu.stat"), "usage_usec 5000000\nthrottled_usec 0\n")
	writeFile(t, filepath.Join(cgRoot, "docker", cid, "memory.current"), "1048576\n")
	writeFile(t, filepath.Join(cgRoot, "docker", cid, "memory.max"), "268435456\n")
	writeFile(t, filepath.Join(cgRoot, "docker", cid, "memory.events"), "oom_kill 0\n")
	writeFile(t, filepath.Join(cgRoot, "docker", cid, "pids.current"), "1\n")

	store := graph.NewStore()
	spec := graph.NodeSpec{ID: "container:" + cid[:12], Kind: graph.NodeContainer, Label: cid[:12], ContainerID: cid, PID: 423}
	store.UpsertNode(spec, time.Unix(1000, 0))
	spec.PID = 9812
	store.UpsertNode(spec, time.Unix(1000, 0))

	sm := NewSampler(store, nil)
	sm.procRoot = procRoot
	sm.cgroupRoot = cgRoot

	t0 := time.Unix(2000, 0)
	sm.Sample(t0)
	sm.Sample(t0.Add(10 * time.Second))

	var node graph.Node
	for _, n := range store.Snapshot().Nodes {
		if n.ID == spec.ID {
			node = n
		}
	}
	if len(node.PIDs) != 1 || node.PIDs[0] != 9812 {
		t.Fatalf("recycled pid not pruned: %v", node.PIDs)
	}
	if node.Metrics == nil {
		t.Fatal("no metrics emitted on the second pass")
	}
	if node.Metrics.RSSBytes != 1048576 {
		t.Fatalf("rss = %d, want the container cgroup's 1048576", node.Metrics.RSSBytes)
	}
	if node.Metrics.MemLimit != 268435456 {
		t.Fatalf("mem limit = %d", node.Metrics.MemLimit)
	}
	if node.Metrics.WindowSecs != 10 {
		t.Fatalf("windowSecs = %d, want 10", node.Metrics.WindowSecs)
	}
}

// A process node's pid that now runs a different executable is foreign:
// its numbers must not fold into the node, and it must be pruned.
func TestSampleProcsRejectsRecycledPid(t *testing.T) {
	dir := t.TempDir()
	procRoot := filepath.Join(dir, "proc")
	exe := filepath.Join(dir, "bin", "app")
	other := filepath.Join(dir, "bin", "other")
	writeFile(t, exe, "")
	writeFile(t, other, "")

	fakePid(t, procRoot, "100", "0::/init.scope\n", exe)
	fakePid(t, procRoot, "200", "0::/init.scope\n", other) // recycled

	store := graph.NewStore()
	spec := graph.NodeSpec{ID: "proc:" + exe, Kind: graph.NodeProcess, Label: "app", Exe: exe, PID: 100}
	store.UpsertNode(spec, time.Unix(1000, 0))
	spec.PID = 200
	store.UpsertNode(spec, time.Unix(1000, 0))

	sm := NewSampler(store, nil)
	sm.procRoot = procRoot

	t0 := time.Unix(2000, 0)
	sm.Sample(t0)
	sm.Sample(t0.Add(10 * time.Second))

	var node graph.Node
	for _, n := range store.Snapshot().Nodes {
		if n.ID == spec.ID {
			node = n
		}
	}
	if len(node.PIDs) != 1 || node.PIDs[0] != 100 {
		t.Fatalf("recycled pid not pruned: %v", node.PIDs)
	}
	if node.Metrics == nil {
		t.Fatal("no metrics emitted")
	}
	if node.Metrics.Procs != 1 {
		t.Fatalf("procs = %d, want 1 (only the verified pid)", node.Metrics.Procs)
	}
	if node.Metrics.RSSBytes != 1250*uint64(os.Getpagesize()) {
		t.Fatalf("rss = %d, want one pid's worth", node.Metrics.RSSBytes)
	}
}

// A node whose pids all vanish stops costing anything: its baseline is
// evicted (bounded memory) and its pid list empties, so later passes
// skip it entirely.
func TestSamplerEvictsVanishedNodes(t *testing.T) {
	dir := t.TempDir()
	procRoot := filepath.Join(dir, "proc")
	exe := filepath.Join(dir, "bin", "app")
	writeFile(t, exe, "")
	fakePid(t, procRoot, "100", "0::/init.scope\n", exe)

	store := graph.NewStore()
	store.UpsertNode(graph.NodeSpec{ID: "proc:" + exe, Kind: graph.NodeProcess, Label: "app", Exe: exe, PID: 100}, time.Unix(1000, 0))

	sm := NewSampler(store, nil)
	sm.procRoot = procRoot
	t0 := time.Unix(2000, 0)
	sm.Sample(t0)
	if len(sm.prev) != 1 {
		t.Fatalf("baseline not stored: %d entries", len(sm.prev))
	}

	// The process dies.
	if err := os.RemoveAll(filepath.Join(procRoot, "100")); err != nil {
		t.Fatal(err)
	}
	sm.Sample(t0.Add(10 * time.Second))
	if len(sm.prev) != 0 {
		t.Fatalf("baseline for vanished node kept: %d entries", len(sm.prev))
	}
	for _, n := range store.Snapshot().Nodes {
		if n.ID == "proc:"+exe && len(n.PIDs) != 0 {
			t.Fatalf("dead pid kept on node: %v", n.PIDs)
		}
	}
}

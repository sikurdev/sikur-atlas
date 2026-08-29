//go:build linux

package procfs

import (
	"sync"
	"time"

	"github.com/sikurdev/sikur-atlas/internal/model"
)

// Resolver resolves PIDs against the live /proc with a small TTL cache.
// It implements collector.ProcessResolver.
type Resolver struct {
	mu    sync.Mutex
	ttl   time.Duration
	cache map[uint32]cachedInfo
}

type cachedInfo struct {
	info    model.ProcessInfo
	expires time.Time
}

func NewResolver() *Resolver {
	return &Resolver{
		ttl:   30 * time.Second,
		cache: make(map[uint32]cachedInfo),
	}
}

// Resolve reads process identity for pid. The kernel-provided comm is
// kept as a fallback for processes that exited before inspection, and to
// detect PID reuse (a cached entry whose comm no longer matches is
// discarded).
func (r *Resolver) Resolve(pid uint32, comm string) model.ProcessInfo {
	now := time.Now()

	r.mu.Lock()
	c, ok := r.cache[pid]
	r.mu.Unlock()
	if ok && now.Before(c.expires) && (comm == "" || c.info.Comm == "" || c.info.Comm == comm) {
		return c.info
	}

	info := model.ProcessInfo{PID: pid, Comm: comm}
	if liveComm := Comm(pid); liveComm != "" {
		info.Comm = liveComm
	}
	info.Exe = Exe(pid)
	info.Cmdline = Cmdline(pid)
	info.ContainerID = ContainerID(pid)

	r.mu.Lock()
	r.cache[pid] = cachedInfo{info: info, expires: now.Add(r.ttl)}
	// Opportunistic bounded cleanup so the cache cannot grow forever.
	if len(r.cache) > 4096 {
		for k, v := range r.cache {
			if now.After(v.expires) {
				delete(r.cache, k)
			}
		}
	}
	r.mu.Unlock()
	return info
}

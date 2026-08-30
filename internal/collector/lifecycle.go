package collector

import (
	"fmt"

	"github.com/sikurdev/sikur-atlas/internal/model"
)

// Lifecycle event kinds as persisted.
const (
	LifeExec  = "exec"
	LifeExit  = "exit"
	LifeCrash = "crash"
	LifeOOM   = "oom"
)

// DetailExitClean is the recorded detail of an orderly exit(0). The
// Incident Lens keys on it: a clean exit is normal lifecycle, never a
// primary incident event.
const DetailExitClean = "exited cleanly"

// crashSignals are the "something is wrong" terminations; ordinary
// SIGTERM/SIGINT/SIGKILL deaths stay plain exits (SIGKILL from the OOM
// killer arrives as its own event).
var crashSignals = map[int]string{
	4:  "SIGILL",
	6:  "SIGABRT",
	7:  "SIGBUS",
	8:  "SIGFPE",
	11: "SIGSEGV",
}

const maxPidNodes = 16384

// handleLifecycle attributes exec/exit/oom events to services already
// on the map. Events for processes Atlas has never associated with a
// node are dropped (counted), which keeps volume bounded to the
// topology instead of every shell command on the host.
func (c *Correlator) handleLifecycle(ev model.ConnEvent) {
	var nodeID string
	var kind, detail string

	switch ev.Type {
	case model.EventExec:
		// Resolve fresh: the pid's identity just changed. buildSpec, not
		// specForProcess — the pid→node memory must only learn pids
		// whose node actually exists, or exits of untracked commands
		// ride the cache past this gate.
		info := c.resolver.Resolve(ev.PID, ev.Comm)
		spec := c.buildSpec(info, "")
		if !c.store.HasNode(spec.ID) {
			c.stats.LifecycleDropped++
			return
		}
		nodeID = spec.ID
		c.rememberPidNode(ev.PID, nodeID)
		kind = LifeExec
		detail = ev.Path
	case model.EventExit:
		nodeID = c.nodeForPid(ev.PID, ev.Comm)
		if nodeID == "" {
			c.stats.LifecycleDropped++
			return
		}
		c.addrMu.Lock()
		delete(c.pidNodes, ev.PID)
		c.addrMu.Unlock()
		kind, detail = decodeExit(ev.Code)
	case model.EventOOM:
		nodeID = c.nodeForPid(ev.PID, "")
		if nodeID == "" {
			c.stats.LifecycleDropped++
			return
		}
		kind = LifeOOM
		detail = fmt.Sprintf("pid %d chosen by the OOM killer", ev.PID)
	default:
		return
	}

	if c.rec != nil {
		c.rec.NodeEvent(nodeID, kind, ev.PID, detail, ev.Time)
	}
}

// decodeExit turns the kernel's raw exit_code into (kind, detail):
// low 7 bits = fatal signal, else status = code >> 8.
func decodeExit(code int32) (string, string) {
	if sig := int(code & 0x7f); sig != 0 {
		if name, crash := crashSignals[sig]; crash {
			return LifeCrash, fmt.Sprintf("killed by %s (signal %d)", name, sig)
		}
		return LifeExit, fmt.Sprintf("killed by signal %d", sig)
	}
	status := int(code >> 8)
	if status == 0 {
		return LifeExit, DetailExitClean
	}
	return LifeExit, fmt.Sprintf("exited with status %d", status)
}

// rememberPidNode caps the pid→node memory so a churn-heavy host cannot
// grow it unboundedly. An already-known pid always updates — refusing
// the overwrite at the cap would freeze stale attributions exactly when
// the host is busiest. Guarded by addrMu: callers run both under and
// outside the correlator's main lock.
func (c *Correlator) rememberPidNode(pid uint32, nodeID string) {
	if pid == 0 {
		return
	}
	c.addrMu.Lock()
	if _, known := c.pidNodes[pid]; known || len(c.pidNodes) < maxPidNodes {
		c.pidNodes[pid] = nodeID
	}
	c.addrMu.Unlock()
}

// nodeForPid finds the node a pid belongs to: last-known mapping first,
// then a live resolve. Every answer is gated on the node existing —
// the cache is planted by connection paths whose nodes may never have
// materialized, and a hit on such an entry must not invent history.
func (c *Correlator) nodeForPid(pid uint32, comm string) string {
	c.addrMu.Lock()
	id, ok := c.pidNodes[pid]
	c.addrMu.Unlock()
	if ok {
		if c.store.HasNode(id) {
			return id
		}
		c.addrMu.Lock()
		delete(c.pidNodes, pid)
		c.addrMu.Unlock()
	}
	info := c.resolver.Resolve(pid, comm)
	if info.Exe == "" && info.ContainerID == "" && comm == "" && info.Comm == "" {
		return ""
	}
	spec := c.buildSpec(info, "")
	if !c.store.HasNode(spec.ID) {
		return ""
	}
	c.rememberPidNode(pid, spec.ID)
	return spec.ID
}

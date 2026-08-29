package collector

import (
	"time"

	"github.com/sikurdev/sikur-atlas/internal/graph"
	"github.com/sikurdev/sikur-atlas/internal/model"
	"github.com/sikurdev/sikur-atlas/internal/unixdiag"
)

// UnixPair is one standing AF_UNIX connection derived from the kernel's
// socket dump.
type UnixPair struct {
	ClientPID   uint32
	ServerPID   uint32
	ClientInode uint32
	ServerInode uint32
	Path        string
}

// pairKey identifies a standing pair across scans.
type pairKey struct{ client, server uint32 }

// BuildUnixPairs turns a socket dump plus inode ownership into directed
// pairs and the path→owner listener table. An edge is generated only
// when an unnamed socket peers with a named one: the named side is the
// server (accepted stream sockets inherit the listener's name, named
// datagram receivers are servers). Unnamed↔unnamed (socketpair) and
// named↔named pairs carry no truthful direction and are skipped.
func BuildUnixPairs(socks []unixdiag.Socket, inodeToPID map[uint64]uint32) ([]UnixPair, map[string]uint32) {
	byInode := make(map[uint32]unixdiag.Socket, len(socks))
	listeners := make(map[string]uint32)
	for _, s := range socks {
		byInode[s.Inode] = s
		if s.Listening() && s.Path != "" {
			if pid, ok := inodeToPID[uint64(s.Inode)]; ok {
				listeners[s.Path] = pid
			}
		}
	}

	var pairs []UnixPair
	for _, s := range socks {
		if s.PeerInode == 0 || s.Path != "" {
			continue // only from the unnamed (client) side
		}
		peer, ok := byInode[s.PeerInode]
		if !ok || peer.Path == "" {
			continue // socketpair or unknown peer: no truthful direction
		}
		cpid, cok := inodeToPID[uint64(s.Inode)]
		spid, sok := inodeToPID[uint64(peer.Inode)]
		if !cok || !sok || cpid == spid {
			// Unattributable or self-loop: nothing useful to draw.
			continue
		}
		pairs = append(pairs, UnixPair{
			ClientPID:   cpid,
			ServerPID:   spid,
			ClientInode: s.Inode,
			ServerInode: peer.Inode,
			Path:        peer.Path,
		})
	}
	return pairs, listeners
}

// SyncUnixTopology applies a fresh AF_UNIX scan: new standing pairs
// raise edges (active++), vanished pairs release them, and the listener
// table updates the path→service index used to attribute connect events
// and failures. Must be called from a single goroutine.
func (c *Correlator) SyncUnixTopology(socks []unixdiag.Socket, inodeToPID map[uint64]uint32, at time.Time) {
	pairs, listeners := BuildUnixPairs(socks, inodeToPID)

	// Refresh the path index (shared with the event path). The listener
	// node is created with its full identity here: a unix-only server
	// (no TCP at all) is otherwise never materialized properly.
	index := make(map[string]string, len(listeners))
	for path, pid := range listeners {
		info := c.resolver.Resolve(pid, "")
		spec := c.specForProcess(info, "")
		c.store.UpsertNode(spec, at)
		index[path] = spec.ID
	}
	c.addrMu.Lock()
	c.unixPathIndex = index
	c.addrMu.Unlock()

	current := make(map[pairKey]bool, len(pairs))
	for _, p := range pairs {
		key := pairKey{client: p.ClientInode, server: p.ServerInode}
		current[key] = true
		if _, known := c.unixPairs[key]; known {
			continue
		}
		clientSpec := c.specForProcess(c.resolver.Resolve(p.ClientPID, ""), "")
		serverSpec := c.specForProcess(c.resolver.Resolve(p.ServerPID, ""), "")
		edgeID := c.store.UnixPairUp(clientSpec, serverSpec, p.Path, at)
		c.unixPairs[key] = edgeID
		if c.rec != nil {
			c.rec.EdgeActive(edgeID, +1, at)
		}
	}
	for key, edgeID := range c.unixPairs {
		if current[key] {
			continue
		}
		c.store.UnixPairDown(edgeID, at)
		if c.rec != nil {
			c.rec.EdgeActive(edgeID, -1, at)
		}
		delete(c.unixPairs, key)
	}
}

// handleUnixConnect processes one BPF connect-return event: successes
// count connections, non-zero returns count failures, both towards the
// service owning the target path (or a placeholder node when nothing is
// known to listen there).
func (c *Correlator) handleUnixConnect(ev model.ConnEvent) {
	if ev.Path == "" {
		return
	}
	info := c.resolver.Resolve(ev.PID, ev.Comm)
	clientSpec := c.specForProcess(info, "")

	c.addrMu.Lock()
	dstID, known := c.unixPathIndex[ev.Path]
	c.addrMu.Unlock()

	var dstSpec graph.NodeSpec
	if known {
		dstSpec = graph.NodeSpec{ID: dstID}
	} else {
		dstSpec = graph.NodeSpec{
			ID:    "unix:" + ev.Path,
			Kind:  graph.NodeExternal,
			Label: ev.Path,
		}
	}

	if ev.Code == 0 {
		edgeID := c.store.UnixConnectObserved(clientSpec, dstSpec, ev.Path, ev.Time)
		if c.rec != nil {
			c.rec.EdgeConnects(edgeID, 1, ev.Time)
		}
	} else {
		c.stats.UnixFailures++
		edgeID := c.store.ObserveUnixFailure(clientSpec, dstSpec, ev.Path, ev.Time)
		if c.rec != nil {
			c.rec.EdgeFailure(edgeID, ev.Time)
		}
	}
}

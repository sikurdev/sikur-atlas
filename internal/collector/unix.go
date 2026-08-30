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
//
// The dump spans every namespace, and the same path string can be bound
// by different processes in different namespaces (abstract names are
// per-netns; filesystem paths are mount-ns relative). Such a path names
// no single owner, so it is dropped from the listener table rather than
// resolved last-wins — connect events to it stay unattributed instead
// of being attributed wrongly. Pairs are unaffected (inode-exact).
func BuildUnixPairs(socks []unixdiag.Socket, inodeToPID map[uint64]uint32) ([]UnixPair, map[string]uint32) {
	byInode := make(map[uint32]unixdiag.Socket, len(socks))
	listeners := make(map[string]uint32)
	ambiguous := make(map[string]bool)
	for _, s := range socks {
		byInode[s.Inode] = s
		if s.Listening() && s.Path != "" {
			pid, ok := inodeToPID[uint64(s.Inode)]
			if !ok {
				continue
			}
			if prev, seen := listeners[s.Path]; seen && prev != pid {
				ambiguous[s.Path] = true
				continue
			}
			listeners[s.Path] = pid
		}
	}
	for path := range ambiguous {
		delete(listeners, path)
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

// unixOwner is one listener-table entry: the owning node plus the full
// bound path (index keys are event-truncated, see eventPathKey).
type unixOwner struct {
	nodeID string
	path   string
}

// eventPathKey normalizes a bound path to what the BPF connect event
// can carry — its buffer holds 64 bytes ("@" plus 63 name bytes for
// abstract sockets) — so index lookups by event paths still match
// listeners bound at longer paths.
func eventPathKey(path string) string {
	if len(path) > 64 {
		return path[:64]
	}
	return path
}

// SyncUnixTopology applies a fresh AF_UNIX scan: new standing pairs
// raise edges (active++), vanished pairs release them, and the listener
// table updates the path→service index used to attribute connect events
// and failures. Must be called from a single goroutine.
func (c *Correlator) SyncUnixTopology(socks []unixdiag.Socket, inodeToPID map[uint64]uint32, at time.Time) {
	pairs, listeners := BuildUnixPairs(socks, inodeToPID)

	// Refresh the path index (shared with the event path). The listener
	// node is created with its full identity here: a unix-only server
	// (no TCP at all) is otherwise never materialized properly. Two
	// distinct long paths collapsing onto one truncated key make that
	// key ambiguous — dropped, same policy as colliding bind paths.
	index := make(map[string]unixOwner, len(listeners))
	truncAmbiguous := make(map[string]bool)
	for path, pid := range listeners {
		info := c.resolver.Resolve(pid, "")
		spec := c.specForProcess(info, "")
		c.store.UpsertNode(spec, at)
		key := eventPathKey(path)
		if prev, seen := index[key]; seen && prev.path != path {
			truncAmbiguous[key] = true
		}
		index[key] = unixOwner{nodeID: spec.ID, path: path}
	}
	for key := range truncAmbiguous {
		delete(index, key)
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
	owner, known := c.unixPathIndex[ev.Path]
	c.addrMu.Unlock()

	var dstSpec graph.NodeSpec
	path := ev.Path
	if known {
		dstSpec = graph.NodeSpec{ID: owner.nodeID}
		// Use the listener's full bound path so event edges and
		// standing-pair edges share one identity even when the event
		// buffer truncated the path.
		path = owner.path
	} else {
		dstSpec = graph.NodeSpec{
			ID:    "unix:" + ev.Path,
			Kind:  graph.NodeExternal,
			Label: ev.Path,
		}
	}

	if ev.Code == 0 {
		edgeID := c.store.UnixConnectObserved(clientSpec, dstSpec, path, ev.Time)
		if c.rec != nil {
			c.rec.EdgeConnects(edgeID, 1, ev.Time)
		}
	} else {
		c.stats.UnixFailures++
		edgeID := c.store.ObserveUnixFailure(clientSpec, dstSpec, path, ev.Time)
		if c.rec != nil {
			c.rec.EdgeFailure(edgeID, ev.Time)
		}
	}
}

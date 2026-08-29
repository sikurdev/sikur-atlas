// Package model holds the plain data types shared by the eBPF event
// pipeline, the correlator and the graph store.
package model

import (
	"net/netip"
	"time"
)

// EventType mirrors enum atlas_event_type in bpf/atlas.bpf.c.
type EventType uint32

const (
	// EventOpen: an outbound connect() was initiated. PID and Comm are
	// trustworthy; the source address/port may not be assigned yet.
	EventOpen EventType = 1
	// EventAccept: an inbound connection was accepted. PID, Comm and the
	// full tuple are trustworthy.
	EventAccept EventType = 2
	// EventEstablished: the handshake completed. Fires in softirq
	// context, so it carries no PID; the tuple is complete.
	EventEstablished EventType = 3
	// EventClose: the socket reached TCP_CLOSE. Carries lifetime byte
	// counters; no PID.
	EventClose EventType = 4
)

func (t EventType) String() string {
	switch t {
	case EventOpen:
		return "open"
	case EventAccept:
		return "accept"
	case EventEstablished:
		return "established"
	case EventClose:
		return "close"
	default:
		return "unknown"
	}
}

// ConnEvent is one decoded kernel event. Src is always the local end of
// the socket the event was observed on, Dst the remote end.
type ConnEvent struct {
	Time      time.Time
	Type      EventType
	PID       uint32 // 0 when the kernel context was not attributable
	Comm      string
	SockID    uint64 // kernel socket identity, stable while the socket lives
	Src       netip.AddrPort
	Dst       netip.AddrPort
	BytesSent uint64 // EventClose only: bytes sent from this socket's side
	BytesRecv uint64 // EventClose only
}

// ProcessInfo is the userspace identity attached to a PID.
type ProcessInfo struct {
	PID         uint32
	Comm        string
	Exe         string // resolved /proc/<pid>/exe, "" if unavailable
	Cmdline     string
	ContainerID string // full 64-hex container id, "" for host processes
}

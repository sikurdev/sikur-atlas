// Package unixdiag dumps the kernel's AF_UNIX socket table (inode, peer
// inode, bound path, state) over NETLINK_SOCK_DIAG. This is the same
// evidence `ss -x` shows: the kernel's own pairing, not an inference.
// Message parsing is portable and unit-tested; the netlink transport is
// Linux-only (dump_linux.go).
package unixdiag

import (
	"encoding/binary"
	"fmt"
)

// Socket states mirror the TCP-style states sock_diag reports for unix
// sockets.
const (
	StateEstablished = 1
	StateListen      = 10
)

// Socket types.
const (
	TypeStream    = 1
	TypeDgram     = 2
	TypeSeqpacket = 5
)

// Attribute kinds (uapi/linux/unix_diag.h).
const (
	attrName = 0
	attrPeer = 2
)

// Socket is one AF_UNIX socket as reported by the kernel.
type Socket struct {
	Inode     uint32
	PeerInode uint32 // 0 = unpeered
	Path      string // "" unnamed, "@name" abstract
	State     uint8
	Type      uint8
}

// Listening reports whether this is a stream/seqpacket listener or a
// named datagram receiver.
func (s Socket) Listening() bool {
	if s.Type == TypeDgram {
		return s.Path != ""
	}
	return s.State == StateListen
}

const diagMsgLen = 16 // unix_diag_msg: family, type, state, pad, ino, cookie[2]

// ParseMessage decodes one SOCK_DIAG_BY_FAMILY payload.
func ParseMessage(data []byte) (Socket, error) {
	if len(data) < diagMsgLen {
		return Socket{}, fmt.Errorf("unix_diag_msg too short: %d bytes", len(data))
	}
	le := binary.LittleEndian
	s := Socket{
		Type:  data[1],
		State: data[2],
		Inode: le.Uint32(data[4:]),
	}

	// Attributes: aligned to 4 bytes, each {len u16, type u16, payload}.
	off := diagMsgLen
	for off+4 <= len(data) {
		alen := int(le.Uint16(data[off:]))
		atype := le.Uint16(data[off+2:])
		if alen < 4 || off+alen > len(data) {
			break
		}
		payload := data[off+4 : off+alen]
		switch atype {
		case attrName:
			s.Path = decodeName(payload)
		case attrPeer:
			if len(payload) >= 4 {
				s.PeerInode = le.Uint32(payload)
			}
		}
		off += (alen + 3) &^ 3
	}
	return s, nil
}

// decodeName renders a sun_path payload: abstract names carry a leading
// NUL and become "@name"; filesystem paths may carry a trailing NUL.
func decodeName(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	if b[0] == 0 {
		return "@" + trimNul(b[1:])
	}
	return trimNul(b)
}

func trimNul(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

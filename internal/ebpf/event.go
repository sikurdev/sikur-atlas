// Package ebpf embeds the compiled BPF object and decodes its events.
// The kernel side of this contract lives in bpf/atlas.bpf.c
// (struct conn_event); TestEventLayoutMatchesBTF pins the two together.
package ebpf

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"time"

	"github.com/sikurdev/sikur-atlas/internal/model"
)

// Offsets into struct conn_event (little-endian, verified against the
// object's BTF by unit test).
const (
	offTsNs      = 0
	offSockID    = 8
	offBytesSent = 16
	offBytesRecv = 24
	offType      = 32
	offPID       = 36
	offComm      = 40
	offSaddr     = 56
	offDaddr     = 72
	offFamily    = 88
	offSport     = 90
	offDport     = 92
	offSrttUs    = 96
	offCode      = 100
	offUpath     = 104
	upathLen     = 64

	// EventSize is sizeof(struct conn_event).
	EventSize = 168
)

// DecodeEvent parses one raw ring buffer record. toTime converts the
// kernel's CLOCK_MONOTONIC nanosecond stamp to wall time.
func DecodeEvent(b []byte, toTime func(nsec uint64) time.Time) (model.ConnEvent, error) {
	if len(b) < EventSize {
		return model.ConnEvent{}, fmt.Errorf("event too short: %d bytes, want %d", len(b), EventSize)
	}
	le := binary.LittleEndian

	var saddr, daddr [16]byte
	copy(saddr[:], b[offSaddr:offSaddr+16])
	copy(daddr[:], b[offDaddr:offDaddr+16])

	ev := model.ConnEvent{
		Time:       toTime(le.Uint64(b[offTsNs:])),
		Type:       model.EventType(le.Uint32(b[offType:])),
		PID:        le.Uint32(b[offPID:]),
		Comm:       commString(b[offComm : offComm+16]),
		SockID:     le.Uint64(b[offSockID:]),
		Src:        addrPort(saddr, le.Uint16(b[offSport:])),
		Dst:        addrPort(daddr, le.Uint16(b[offDport:])),
		BytesSent:  le.Uint64(b[offBytesSent:]),
		BytesRecv:  le.Uint64(b[offBytesRecv:]),
		SRTTMicros: le.Uint32(b[offSrttUs:]),
		Code:       int32(le.Uint32(b[offCode:])),
		Path:       pathString(b[offUpath : offUpath+upathLen]),
	}
	return ev, nil
}

// pathString decodes the kernel-truncated path buffer. An abstract unix
// socket name arrives with a leading NUL and is rendered "@name".
func pathString(b []byte) string {
	if len(b) == 0 || b[0] == 0 && (len(b) < 2 || b[1] == 0) {
		return ""
	}
	if b[0] == 0 {
		return "@" + commString(b[1:])
	}
	return commString(b)
}

// addrPort builds an AddrPort from the kernel's 16-byte representation.
// AF_INET addresses arrive v4-mapped (::ffff:a.b.c.d) and are unmapped so
// the rest of the pipeline sees plain IPv4.
func addrPort(raw [16]byte, port uint16) netip.AddrPort {
	return netip.AddrPortFrom(netip.AddrFrom16(raw).Unmap(), port)
}

func commString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

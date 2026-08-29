// Package procfs parses the /proc surfaces Atlas needs: process
// identity, container membership and listening sockets. Parsers are
// portable and unit-tested; the walking code that touches a live /proc
// is Linux-only (see scan_linux.go).
package procfs

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// containerIDRe matches the 64-hex container id docker, containerd and
// podman all embed in cgroup paths (both cgroup v1 and v2 layouts).
var containerIDRe = regexp.MustCompile(`[0-9a-f]{64}`)

// ParseCgroupContainerID extracts a container id from /proc/<pid>/cgroup
// content, or returns "".
func ParseCgroupContainerID(r io.Reader) string {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		if id := containerIDRe.FindString(sc.Text()); id != "" {
			return id
		}
	}
	return ""
}

// ListenSocket is one LISTEN-state row from /proc/net/tcp{,6}.
type ListenSocket struct {
	Addr  netip.Addr
	Port  uint16
	Inode uint64
}

const tcpStateListen = "0A"

// ParseTCPListeners parses /proc/net/tcp or /proc/net/tcp6 content and
// returns the LISTEN sockets.
func ParseTCPListeners(r io.Reader) []ListenSocket {
	var out []ListenSocket
	sc := bufio.NewScanner(r)
	first := true
	for sc.Scan() {
		if first { // header row
			first = false
			continue
		}
		fields := strings.Fields(sc.Text())
		// sl local_address rem_address st ... inode ...
		if len(fields) < 10 || fields[3] != tcpStateListen {
			continue
		}
		addr, port, ok := parseHexAddrPort(fields[1])
		if !ok {
			continue
		}
		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil {
			continue
		}
		out = append(out, ListenSocket{Addr: addr, Port: port, Inode: inode})
	}
	return out
}

// parseHexAddrPort decodes the kernel's "0100007F:1F90" (v4) or 32-hex:port
// (v6) socket address encoding. IPv4 addresses and each 32-bit group of
// IPv6 addresses are little-endian on x86.
func parseHexAddrPort(s string) (netip.Addr, uint16, bool) {
	host, portHex, ok := strings.Cut(s, ":")
	if !ok {
		return netip.Addr{}, 0, false
	}
	port64, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return netip.Addr{}, 0, false
	}
	raw, err := hex.DecodeString(host)
	if err != nil {
		return netip.Addr{}, 0, false
	}
	switch len(raw) {
	case 4:
		// Little-endian u32.
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], binary.BigEndian.Uint32(raw))
		return netip.AddrFrom4(b), uint16(port64), true
	case 16:
		var b [16]byte
		for i := 0; i < 4; i++ {
			g := binary.BigEndian.Uint32(raw[i*4:])
			binary.LittleEndian.PutUint32(b[i*4:], g)
		}
		return netip.AddrFrom16(b).Unmap(), uint16(port64), true
	default:
		return netip.Addr{}, 0, false
	}
}

// ParseSocketInode extracts the inode from an fd symlink target like
// "socket:[12345]"; returns 0 when the fd is not a socket.
func ParseSocketInode(link string) uint64 {
	rest, ok := strings.CutPrefix(link, "socket:[")
	if !ok {
		return 0
	}
	numStr, ok := strings.CutSuffix(rest, "]")
	if !ok {
		return 0
	}
	n, err := strconv.ParseUint(numStr, 10, 64)
	if err != nil {
		return 0
	}
	return n
}

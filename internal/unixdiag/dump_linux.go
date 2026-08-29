//go:build linux

package unixdiag

import (
	"encoding/binary"
	"fmt"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	sockDiagByFamily = 20
	// UDIAG_SHOW_NAME | UDIAG_SHOW_PEER
	showNamePeer = 0x1 | 0x4
)

// Dump returns every AF_UNIX socket the kernel reports.
func Dump() ([]Socket, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_SOCK_DIAG)
	if err != nil {
		return nil, fmt.Errorf("sock_diag socket: %w", err)
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, fmt.Errorf("sock_diag bind: %w", err)
	}
	tv := unix.NsecToTimeval(int64(3 * time.Second))
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)

	// nlmsghdr(16) + unix_diag_req(24)
	req := make([]byte, 40)
	le := binary.LittleEndian
	le.PutUint32(req[0:], 40)
	le.PutUint16(req[4:], sockDiagByFamily)
	le.PutUint16(req[6:], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	le.PutUint32(req[8:], 1) // seq
	req[16] = unix.AF_UNIX
	le.PutUint32(req[20:], ^uint32(0)) // all states
	le.PutUint32(req[28:], showNamePeer)
	if err := unix.Sendto(fd, req, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, fmt.Errorf("sock_diag request: %w", err)
	}

	var out []Socket
	buf := make([]byte, 1<<16)
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			return nil, fmt.Errorf("sock_diag recv: %w", err)
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return nil, fmt.Errorf("netlink parse: %w", err)
		}
		for _, m := range msgs {
			switch m.Header.Type {
			case unix.NLMSG_DONE:
				return out, nil
			case unix.NLMSG_ERROR:
				return nil, fmt.Errorf("sock_diag error message")
			case sockDiagByFamily:
				s, err := ParseMessage(m.Data)
				if err == nil {
					out = append(out, s)
				}
			}
		}
	}
}

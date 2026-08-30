//go:build linux

package unixdiag

import (
	"encoding/binary"
	"fmt"
	"os"
	"runtime"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	sockDiagByFamily = 20
	// UDIAG_SHOW_NAME | UDIAG_SHOW_PEER
	showNamePeer = 0x1 | 0x4
)

// Dump returns every AF_UNIX socket visible in the calling process's
// own network namespace. AF_UNIX sockets belong to the namespace of
// the process that created them, so this alone misses every socket
// inside a container; use DumpAll for whole-host coverage.
func Dump() ([]Socket, error) {
	return dumpCurrentNetns()
}

// DumpAll dumps the AF_UNIX socket table of every network namespace,
// entering each via setns on /proc/<pid>/ns/net (one representative
// pid per namespace, as procfs.ScanSockets collects). Sockets are
// deduplicated by inode; a namespace whose representative exited is
// skipped. Requires CAP_SYS_ADMIN.
func DumpAll(nsPids []uint32) ([]Socket, error) {
	if len(nsPids) == 0 {
		return dumpCurrentNetns()
	}
	seen := make(map[uint32]bool)
	var out []Socket
	var lastErr error
	dumped := 0
	for _, pid := range nsPids {
		socks, err := dumpInNetns(pid)
		if err != nil {
			lastErr = err
			continue
		}
		dumped++
		for _, s := range socks {
			if seen[s.Inode] {
				continue
			}
			seen[s.Inode] = true
			out = append(out, s)
		}
	}
	if dumped == 0 && lastErr != nil {
		return nil, lastErr
	}
	return out, nil
}

// dumpInNetns runs one dump inside pid's network namespace, on its own
// goroutine. The goroutine locks its OS thread before setns and unlocks
// only after the namespace is verifiably restored; when the restore
// fails, the goroutine exits still locked, so the runtime destroys the
// thread instead of returning one stuck in a foreign namespace to the
// scheduler pool. (Merely leaving the caller's thread locked would not
// contain anything — the caller keeps running on it.)
func dumpInNetns(pid uint32) ([]Socket, error) {
	type result struct {
		socks []Socket
		err   error
	}
	ch := make(chan result, 1)
	go func() {
		runtime.LockOSThread()
		socks, restored, err := dumpLockedInNetns(pid)
		if restored {
			runtime.UnlockOSThread()
		}
		ch <- result{socks, err}
	}()
	r := <-ch
	return r.socks, r.err
}

// dumpLockedInNetns must run on a locked OS thread. restored reports
// whether the thread is back in its original network namespace and
// therefore safe to reuse.
func dumpLockedInNetns(pid uint32) (socks []Socket, restored bool, err error) {
	self, err := os.Open("/proc/thread-self/ns/net")
	if err != nil {
		return nil, true, fmt.Errorf("open own netns: %w", err)
	}
	defer self.Close()
	target, err := os.Open(fmt.Sprintf("/proc/%d/ns/net", pid))
	if err != nil {
		return nil, true, fmt.Errorf("open netns of pid %d: %w", pid, err)
	}
	defer target.Close()
	if err := unix.Setns(int(target.Fd()), unix.CLONE_NEWNET); err != nil {
		return nil, true, fmt.Errorf("setns to pid %d: %w", pid, err)
	}
	socks, dumpErr := dumpCurrentNetns()
	if err := unix.Setns(int(self.Fd()), unix.CLONE_NEWNET); err != nil {
		return nil, false, fmt.Errorf("restore netns: %w", err)
	}
	return socks, true, dumpErr
}

func dumpCurrentNetns() ([]Socket, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_SOCK_DIAG)
	if err != nil {
		return nil, fmt.Errorf("sock_diag socket: %w", err)
	}
	defer func() { _ = unix.Close(fd) }()
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

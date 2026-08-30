//go:build linux

package procfs

import (
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Listener is a listening TCP socket attributed to a process.
type Listener struct {
	PID  uint32
	Comm string
	Addr netip.Addr
	Port uint16
}

// ContainerID reads the container id for a pid, "" for host processes.
func ContainerID(pid uint32) string {
	f, err := os.Open(procPath(pid, "cgroup"))
	if err != nil {
		return ""
	}
	defer f.Close()
	return ParseCgroupContainerID(f)
}

// Exe resolves /proc/<pid>/exe; "" when unavailable (kernel threads,
// exited or inaccessible processes).
func Exe(pid uint32) string {
	target, err := os.Readlink(procPath(pid, "exe"))
	if err != nil {
		return ""
	}
	// A deleted binary reads as "/path (deleted)"; keep the path.
	return strings.TrimSuffix(target, " (deleted)")
}

// Comm reads /proc/<pid>/comm without the trailing newline.
func Comm(pid uint32) string {
	b, err := os.ReadFile(procPath(pid, "comm"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// Cmdline reads the NUL-separated command line as a spaced string.
func Cmdline(pid uint32) string {
	b, err := os.ReadFile(procPath(pid, "cmdline"))
	if err != nil {
		return ""
	}
	s := strings.TrimRight(string(b), "\x00")
	return strings.ReplaceAll(s, "\x00", " ")
}

func procPath(pid uint32, parts ...string) string {
	return filepath.Join(append([]string{"/proc", strconv.FormatUint(uint64(pid), 10)}, parts...)...)
}

// EstabConn is one established TCP connection found by the socket-table
// scan, attributed to its owning process where the fd walk found one.
type EstabConn struct {
	PID    uint32 // 0 = no owning process found (unattributable)
	Comm   string // "" when PID is 0
	Local  netip.AddrPort
	Remote netip.AddrPort
	Inode  uint64
	// LocalListen reports whether the same network namespace has a
	// listener covering Local (same port, wildcard or equal address) —
	// kernel evidence that this socket is the accepted (server) side.
	LocalListen bool
}

// ScanResult is one pass over /proc's socket-owning processes.
type ScanResult struct {
	Listeners []Listener
	// Established holds every standing TCP connection across the scanned
	// network namespaces; the startup seed and the seed re-verification
	// both consume it.
	Established []EstabConn
	// InodeToPID maps any socket inode (TCP and unix alike) to the
	// first process found holding it.
	InodeToPID map[uint64]uint32
	// NetNSPids holds one representative pid per network namespace.
	// AF_UNIX sockets are only visible to a sock_diag dump made from
	// their own namespace, so the dump must visit each of these.
	NetNSPids []uint32
}

// ScanSockets walks /proc once and returns every listening and
// established TCP socket with its owning process, plus the socket-inode
// ownership map (which also covers AF_UNIX sockets — inodes are inodes).
// Because /proc/<pid>/net/tcp shows that pid's network namespace, one
// representative per namespace is parsed, which covers containers as
// well as the host.
func ScanSockets() ScanResult {
	pids := listPIDs()

	// socket inode -> owning pid, via each process's fd table.
	inodeToPID := make(map[uint64]uint32)
	// network namespace -> representative pid.
	nsRep := make(map[string]uint32)

	for _, pid := range pids {
		fdDir := procPath(pid, "fd")
		entries, err := os.ReadDir(fdDir)
		if err != nil {
			continue // exited or inaccessible
		}
		for _, e := range entries {
			target, err := os.Readlink(filepath.Join(fdDir, e.Name()))
			if err != nil {
				continue
			}
			if inode := ParseSocketInode(target); inode != 0 {
				if _, taken := inodeToPID[inode]; !taken {
					inodeToPID[inode] = pid
				}
			}
		}
		if ns, err := os.Readlink(procPath(pid, "ns", "net")); err == nil {
			if _, ok := nsRep[ns]; !ok {
				nsRep[ns] = pid
			}
		}
	}

	nsPids := make([]uint32, 0, len(nsRep))
	for _, rep := range nsRep {
		nsPids = append(nsPids, rep)
	}

	var out []Listener
	var estab []EstabConn
	commCache := make(map[uint32]string)
	for _, rep := range nsRep {
		// One namespace at a time: listener coverage for the established
		// rows must come from the same namespace's tables.
		var nsListen []ListenSocket
		var nsEstab []EstabSocket
		for _, table := range []string{"net/tcp", "net/tcp6"} {
			f, err := os.Open(procPath(rep, table))
			if err != nil {
				continue
			}
			listeners, established := ParseTCPTable(f)
			f.Close()
			nsListen = append(nsListen, listeners...)
			nsEstab = append(nsEstab, established...)
		}
		for _, s := range nsListen {
			pid, ok := inodeToPID[s.Inode]
			if !ok {
				continue
			}
			comm, ok := commCache[pid]
			if !ok {
				comm = Comm(pid)
				commCache[pid] = comm
			}
			out = append(out, Listener{PID: pid, Comm: comm, Addr: s.Addr, Port: s.Port})
		}
		for _, s := range nsEstab {
			c := EstabConn{
				Local:       s.Local,
				Remote:      s.Remote,
				Inode:       s.Inode,
				LocalListen: listenerCovers(nsListen, s.Local),
			}
			if pid, ok := inodeToPID[s.Inode]; ok {
				c.PID = pid
				comm, ok := commCache[pid]
				if !ok {
					comm = Comm(pid)
					commCache[pid] = comm
				}
				c.Comm = comm
			}
			estab = append(estab, c)
		}
	}
	return ScanResult{Listeners: out, Established: estab, InodeToPID: inodeToPID, NetNSPids: nsPids}
}

// listenerCovers reports whether a listener in the same namespace covers
// the local end of an established socket: same port, and either a
// wildcard bind or the exact address.
func listenerCovers(listeners []ListenSocket, local netip.AddrPort) bool {
	for _, l := range listeners {
		if l.Port != local.Port() {
			continue
		}
		if l.Addr.IsUnspecified() || l.Addr == local.Addr() {
			return true
		}
	}
	return false
}

func listPIDs() []uint32 {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var pids []uint32
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		n, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil {
			continue
		}
		pids = append(pids, uint32(n))
	}
	return pids
}

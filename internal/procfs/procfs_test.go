package procfs

import (
	"strings"
	"testing"
)

func TestParseCgroupContainerID(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{
			name: "cgroup v2 docker systemd",
			in:   "0::/system.slice/docker-4a1f3c9b8d2e4a1f3c9b8d2e4a1f3c9b8d2e4a1f3c9b8d2e4a1f3c9b8d2e4a1f.scope\n",
			want: "4a1f3c9b8d2e4a1f3c9b8d2e4a1f3c9b8d2e4a1f3c9b8d2e4a1f3c9b8d2e4a1f",
		},
		{
			name: "cgroup v1 docker",
			in: "12:pids:/docker/deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\n" +
				"11:memory:/docker/deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\n",
			want: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
		},
		{
			name: "host process",
			in:   "0::/user.slice/user-1000.slice/session-3.scope\n",
			want: "",
		},
		{
			name: "short hex is not a container",
			in:   "0::/system.slice/docker-abc123.scope\n",
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ParseCgroupContainerID(strings.NewReader(tc.in)); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// Real /proc/net/tcp shape (columns beyond inode omitted by the kernel
// only after position 17; we include the tail counters).
const tcpFixture = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 42424 1 0000000000000000 100 0 0 10 0
   1: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 31337 1 0000000000000000 100 0 0 10 0
   2: 0100007F:9C40 0100007F:1F90 01 00000000:00000000 00:00000000 00000000  1000        0 55555 1 0000000000000000 20 4 30 10 -1
`

func TestParseTCPListenersV4(t *testing.T) {
	got := ParseTCPListeners(strings.NewReader(tcpFixture))
	if len(got) != 2 {
		t.Fatalf("listeners = %d, want 2 (ESTABLISHED row must be skipped)", len(got))
	}
	if got[0].Addr.String() != "127.0.0.1" || got[0].Port != 8080 || got[0].Inode != 42424 {
		t.Fatalf("row 0 = %+v", got[0])
	}
	if got[1].Addr.String() != "0.0.0.0" || got[1].Port != 80 || got[1].Inode != 31337 {
		t.Fatalf("row 1 = %+v", got[1])
	}
}

const tcp6Fixture = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:1BB9 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 77777 1 0000000000000000 100 0 0 10 0
   1: 0000000000000000FFFF00000100007F:0FC8 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 88888 1 0000000000000000 100 0 0 10 0
`

func TestParseTCPListenersV6(t *testing.T) {
	got := ParseTCPListeners(strings.NewReader(tcp6Fixture))
	if len(got) != 2 {
		t.Fatalf("listeners = %d, want 2", len(got))
	}
	if got[0].Addr.String() != "::" || got[0].Port != 7097 {
		t.Fatalf("row 0 = %+v", got[0])
	}
	// v4-mapped ::ffff:127.0.0.1 must unmap to plain IPv4.
	if got[1].Addr.String() != "127.0.0.1" || got[1].Port != 4040 {
		t.Fatalf("row 1 = %+v", got[1])
	}
}

func TestParseSocketInode(t *testing.T) {
	if got := ParseSocketInode("socket:[12345]"); got != 12345 {
		t.Fatalf("got %d", got)
	}
	for _, bad := range []string{"pipe:[999]", "/dev/null", "socket:[x]", "socket:12345"} {
		if got := ParseSocketInode(bad); got != 0 {
			t.Fatalf("%q parsed to %d, want 0", bad, got)
		}
	}
}

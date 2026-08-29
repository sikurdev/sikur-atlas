package ebpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"

	"github.com/sikurdev/sikur-atlas/internal/model"
)

// TestEventLayoutMatchesBTF pins the Go decoder offsets to the C struct
// as actually compiled, by reading the BTF out of the built object. This
// runs on any OS — it only parses the ELF.
func TestEventLayoutMatchesBTF(t *testing.T) {
	obj, err := ObjectBytes()
	if err != nil {
		t.Skipf("BPF object not built (run `make bpf`): %v", err)
	}
	spec, err := cebpf.LoadCollectionSpecFromReader(bytes.NewReader(obj))
	if err != nil {
		t.Fatalf("parsing BPF object: %v", err)
	}
	var st *btf.Struct
	if err := spec.Types.TypeByName("conn_event", &st); err != nil {
		t.Fatalf("struct conn_event not in BTF: %v", err)
	}
	if st.Size != EventSize {
		t.Fatalf("sizeof(conn_event) = %d, Go decoder assumes %d", st.Size, EventSize)
	}

	wantOffsets := map[string]uint32{
		"ts_ns":      offTsNs,
		"sock_id":    offSockID,
		"bytes_sent": offBytesSent,
		"bytes_recv": offBytesRecv,
		"type":       offType,
		"pid":        offPID,
		"comm":       offComm,
		"saddr":      offSaddr,
		"daddr":      offDaddr,
		"family":     offFamily,
		"sport":      offSport,
		"dport":      offDport,
	}
	seen := map[string]bool{}
	for _, m := range st.Members {
		want, ok := wantOffsets[m.Name]
		if !ok {
			continue
		}
		seen[m.Name] = true
		if got := m.Offset.Bytes(); got != want {
			t.Errorf("field %s at offset %d in BTF, Go decoder assumes %d", m.Name, got, want)
		}
	}
	for name := range wantOffsets {
		if !seen[name] {
			t.Errorf("field %s missing from struct conn_event", name)
		}
	}
}

// TestObjectHasProgramsAndMaps guards the names the loader attaches by.
func TestObjectHasProgramsAndMaps(t *testing.T) {
	obj, err := ObjectBytes()
	if err != nil {
		t.Skipf("BPF object not built (run `make bpf`): %v", err)
	}
	spec, err := cebpf.LoadCollectionSpecFromReader(bytes.NewReader(obj))
	if err != nil {
		t.Fatalf("parsing BPF object: %v", err)
	}
	for _, prog := range []string{"atlas_sock_set_state", "atlas_inet_csk_accept_ret"} {
		if spec.Programs[prog] == nil {
			t.Errorf("program %q missing; have %v", prog, keys(spec.Programs))
		}
	}
	for _, m := range []string{"events", "drop_count"} {
		if spec.Maps[m] == nil {
			t.Errorf("map %q missing; have %v", m, keys(spec.Maps))
		}
	}
	if p := spec.Programs["atlas_sock_set_state"]; p != nil && p.Type != cebpf.TracePoint {
		t.Errorf("atlas_sock_set_state type = %v, want TracePoint", p.Type)
	}
	if p := spec.Programs["atlas_inet_csk_accept_ret"]; p != nil && p.Type != cebpf.Kprobe {
		t.Errorf("atlas_inet_csk_accept_ret type = %v, want Kprobe", p.Type)
	}
}

func keys[V any](m map[string]V) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestDecodeEvent(t *testing.T) {
	b := make([]byte, EventSize)
	le := binary.LittleEndian
	le.PutUint64(b[offTsNs:], 1_000_000_000)
	le.PutUint64(b[offSockID:], 0xdeadbeef)
	le.PutUint64(b[offBytesSent:], 42)
	le.PutUint64(b[offBytesRecv:], 4242)
	le.PutUint32(b[offType:], uint32(model.EventClose))
	le.PutUint32(b[offPID:], 1234)
	copy(b[offComm:], "curl\x00garbage")
	// v4-mapped 127.0.0.1
	v4mapped := [16]byte{10: 0xff, 11: 0xff, 12: 127, 13: 0, 14: 0, 15: 1}
	copy(b[offSaddr:], v4mapped[:])
	copy(b[offDaddr:], v4mapped[:])
	le.PutUint16(b[offFamily:], 2)
	le.PutUint16(b[offSport:], 41000)
	le.PutUint16(b[offDport:], 8080)

	base := time.Date(2026, 8, 29, 0, 0, 0, 0, time.UTC)
	ev, err := DecodeEvent(b, func(ns uint64) time.Time {
		return base.Add(time.Duration(ns))
	})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Type != model.EventClose || ev.PID != 1234 || ev.Comm != "curl" {
		t.Fatalf("decoded %+v", ev)
	}
	if !ev.Time.Equal(base.Add(time.Second)) {
		t.Fatalf("time = %v", ev.Time)
	}
	if ev.Src.String() != "127.0.0.1:41000" || ev.Dst.String() != "127.0.0.1:8080" {
		t.Fatalf("addrs = %v -> %v, want unmapped IPv4", ev.Src, ev.Dst)
	}
	if ev.BytesSent != 42 || ev.BytesRecv != 4242 || ev.SockID != 0xdeadbeef {
		t.Fatalf("decoded %+v", ev)
	}

	if _, err := DecodeEvent(b[:10], func(uint64) time.Time { return base }); err == nil {
		t.Fatal("short event must error")
	}
}

func TestDecodeEventIPv6(t *testing.T) {
	b := make([]byte, EventSize)
	le := binary.LittleEndian
	le.PutUint32(b[offType:], uint32(model.EventEstablished))
	v6 := [16]byte{0: 0x20, 1: 0x01, 2: 0x0d, 3: 0xb8, 15: 0x01}
	copy(b[offSaddr:], v6[:])
	le.PutUint16(b[offFamily:], 10)
	le.PutUint16(b[offSport:], 443)

	ev, err := DecodeEvent(b, func(uint64) time.Time { return time.Time{} })
	if err != nil {
		t.Fatal(err)
	}
	if got := ev.Src.String(); got != "[2001:db8::1]:443" {
		t.Fatalf("src = %s", got)
	}
}

func init() {
	// Guard against accidental struct drift making EventSize inconsistent
	// with the field offsets above.
	if offDport+2+2 != EventSize {
		panic(fmt.Sprintf("event layout constants inconsistent: %d", offDport+4))
	}
}

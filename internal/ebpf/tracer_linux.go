//go:build linux

package ebpf

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/sikurdev/sikur-atlas/internal/model"
)

// Tracer owns the loaded BPF collection, its attachments and the ring
// buffer reader.
type Tracer struct {
	coll   *cebpf.Collection
	links  []link.Link
	reader *ringbuf.Reader
	// monoBase converts CLOCK_MONOTONIC nanoseconds (bpf_ktime_get_ns)
	// to wall time.
	monoBase time.Time
	// missing names capabilities that could not attach on this kernel
	// (see Missing).
	missing []string
}

// Capability names reported by Missing when the kernel cannot attach
// the kprobe-based programs (e.g. built without CONFIG_KPROBES).
const (
	// MissingAcceptAttribution: no kretprobe on inet_csk_accept — the
	// server side of connections cannot be attributed to its process
	// and shows as an external endpoint (the documented semantics for
	// an unidentified half).
	MissingAcceptAttribution = "server-accept-attribution"
	// MissingUnixConnectEvents: no probes on unix_stream_connect —
	// AF_UNIX connect/failure rates are not counted. Standing AF_UNIX
	// pairs still come from the sock_diag socket-table scan.
	MissingUnixConnectEvents = "unix-connect-events"
)

// Missing lists capabilities this kernel could not provide, in
// deterministic order; empty on any mainstream kernel. Callers surface
// it loudly (log, /api/meta) — degradation is announced, never silent.
func (t *Tracer) Missing() []string { return t.missing }

// NewTracer loads the embedded BPF object into the kernel and attaches
// both programs. Requires root or CAP_BPF+CAP_PERFMON (plus kernel
// >= 5.8 with BTF, see docs/architecture.md).
func NewTracer() (*Tracer, error) {
	obj, err := ObjectBytes()
	if err != nil {
		return nil, err
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("raising memlock rlimit: %w", err)
	}
	spec, err := cebpf.LoadCollectionSpecFromReader(bytes.NewReader(obj))
	if err != nil {
		return nil, fmt.Errorf("parsing BPF object: %w", err)
	}
	coll, err := cebpf.NewCollection(spec)
	if err != nil {
		var ve *cebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("kernel rejected BPF program: %+v", ve)
		}
		return nil, fmt.Errorf("loading BPF collection: %w", err)
	}

	t := &Tracer{coll: coll}
	ok := false
	defer func() {
		if !ok {
			t.Close()
		}
	}()

	for _, tp := range []struct {
		group, name, prog string
	}{
		{"sock", "inet_sock_set_state", "atlas_sock_set_state"},
		{"tcp", "tcp_retransmit_skb", "atlas_tcp_retransmit"},
		{"tcp", "tcp_receive_reset", "atlas_tcp_receive_reset"},
		{"sched", "sched_process_exec", "atlas_process_exec"},
		{"sched", "sched_process_exit", "atlas_process_exit"},
		{"oom", "mark_victim", "atlas_oom_victim"},
	} {
		l, err := link.Tracepoint(tp.group, tp.name, coll.Programs[tp.prog], nil)
		if err != nil {
			return nil, fmt.Errorf("attaching tracepoint %s/%s: %w", tp.group, tp.name, err)
		}
		t.links = append(t.links, l)
	}

	// The kprobe-based programs are attribution enrichment, not the
	// spine: a kernel that cannot attach kprobes at all (built without
	// CONFIG_KPROBES — some hardened/minimal VM kernels) still gets the
	// full tracepoint pipeline, the socket-table seed and the sock_diag
	// scans. Refusing to start would serve nobody; degrading *silently*
	// would be worse — so failures land in t.missing, which main logs
	// and /api/meta exposes.

	// AF_UNIX connect visibility: entry captures target path + inode,
	// return reports the outcome. Entry and return only make sense as a
	// pair; if either fails, both are dropped.
	ke, keErr := link.Kprobe("unix_stream_connect",
		coll.Programs["atlas_unix_connect_entry"], nil)
	if keErr == nil {
		kr, err := link.Kretprobe("unix_stream_connect",
			coll.Programs["atlas_unix_connect_ret"],
			&link.KprobeOptions{RetprobeMaxActive: 128})
		if err != nil {
			kr, err = link.Kretprobe("unix_stream_connect",
				coll.Programs["atlas_unix_connect_ret"], nil)
		}
		if err != nil {
			ke.Close()
			t.missing = append(t.missing, MissingUnixConnectEvents)
		} else {
			t.links = append(t.links, ke, kr)
		}
	} else {
		t.missing = append(t.missing, MissingUnixConnectEvents)
	}

	// Raise maxactive: with the default, a burst of parallel accept()
	// returns exhausts kretprobe instances and silently drops server
	// attribution. Not every attach mechanism supports the option, so
	// fall back to the default rather than failing.
	kp, err := link.Kretprobe("inet_csk_accept",
		coll.Programs["atlas_inet_csk_accept_ret"],
		&link.KprobeOptions{RetprobeMaxActive: 128})
	if err != nil {
		kp, err = link.Kretprobe("inet_csk_accept",
			coll.Programs["atlas_inet_csk_accept_ret"], nil)
	}
	if err != nil {
		t.missing = append(t.missing, MissingAcceptAttribution)
	} else {
		t.links = append(t.links, kp)
	}

	rd, err := ringbuf.NewReader(coll.Maps["events"])
	if err != nil {
		return nil, fmt.Errorf("opening ring buffer: %w", err)
	}
	t.reader = rd

	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return nil, fmt.Errorf("reading CLOCK_MONOTONIC: %w", err)
	}
	t.monoBase = time.Now().Add(-time.Duration(ts.Nano()))

	ok = true
	return t, nil
}

// Run reads events until ctx is cancelled, passing each decoded event to
// handle. Undecodable records are counted through onError and skipped.
func (t *Tracer) Run(ctx context.Context, handle func(model.ConnEvent), onError func(error)) error {
	go func() {
		<-ctx.Done()
		t.reader.Close() // unblocks Read
	}()
	for {
		rec, err := t.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return ctx.Err()
			}
			return fmt.Errorf("reading ring buffer: %w", err)
		}
		ev, err := DecodeEvent(rec.RawSample, t.toTime)
		if err != nil {
			if onError != nil {
				onError(err)
			}
			continue
		}
		handle(ev)
	}
}

func (t *Tracer) toTime(ns uint64) time.Time {
	return t.monoBase.Add(time.Duration(ns))
}

// Drops sums the kernel-side ring buffer drop counter across CPUs.
func (t *Tracer) Drops() (uint64, error) {
	m := t.coll.Maps["drop_count"]
	if m == nil {
		return 0, errors.New("drop_count map missing")
	}
	var perCPU []uint64
	if err := m.Lookup(uint32(0), &perCPU); err != nil {
		return 0, err
	}
	var total uint64
	for _, v := range perCPU {
		total += v
	}
	return total, nil
}

// Close detaches programs and releases all kernel resources.
func (t *Tracer) Close() {
	if t.reader != nil {
		t.reader.Close()
	}
	for _, l := range t.links {
		l.Close()
	}
	if t.coll != nil {
		t.coll.Close()
	}
}

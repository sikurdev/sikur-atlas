// SPDX-License-Identifier: GPL-2.0
/*
 * atlas.bpf.c — TCP connection lifecycle tracer for Sikur Atlas.
 *
 * Two attach points, chosen for stability and truthful attribution:
 *
 *  1. tracepoint sock:inet_sock_set_state (stable tracepoint ABI)
 *     - TCP_SYN_SENT: an outbound connect() in process context; the current
 *       task is the connection owner, so we capture pid/comm here.
 *     - TCP_ESTABLISHED: fires in softirq context (no trustworthy pid);
 *       confirms the handshake finished. Correlated by socket identity.
 *     - TCP_CLOSE: also softirq; we read the socket's lifetime byte
 *       counters from struct tcp_sock before it is destroyed.
 *
 *  2. kretprobe inet_csk_accept
 *     - Runs when accept() returns in the server process context; the
 *       current task is the accepting process, giving truthful server-side
 *       pid/comm for the new socket.
 *
 * Events stream to userspace over a ring buffer. No packet payloads are
 * ever read — only connection metadata (addresses, ports, byte counts).
 */
#include "vmlinux_min.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"
#include "bpf_endian.h"

char LICENSE[] SEC("license") = "GPL";

enum atlas_event_type {
	ATLAS_EV_OPEN = 1,        /* outbound connect initiated (has pid) */
	ATLAS_EV_ACCEPT = 2,      /* inbound connection accepted (has pid) */
	ATLAS_EV_ESTABLISHED = 3, /* handshake completed (pid unknown, has rtt) */
	ATLAS_EV_CLOSE = 4,       /* socket closed (has bytes and rtt) */
	ATLAS_EV_RETRANS = 5,     /* one segment retransmitted (sock_id only) */
	ATLAS_EV_RST_RECV = 6,    /* RST received on a socket (sock_id only) */
};

/* Wire format shared with the Go side (internal/ebpf/event.go). Layout is
 * fixed little-endian, members ordered by alignment; a unit test checks
 * this struct's BTF against the Go decoder. */
struct conn_event {
	__u64 ts_ns;      /* bpf_ktime_get_ns at emission */
	__u64 sock_id;    /* kernel address of struct sock: stable id while open */
	__u64 bytes_sent; /* ATLAS_EV_CLOSE only, else 0 */
	__u64 bytes_recv; /* ATLAS_EV_CLOSE only, else 0 */
	__u32 type;       /* enum atlas_event_type */
	__u32 pid;        /* owning tgid, 0 if not in a trustworthy context */
	__u8 comm[16];    /* task comm when pid != 0 */
	__u8 saddr[16];   /* local address, v4-mapped for AF_INET */
	__u8 daddr[16];   /* remote address, v4-mapped for AF_INET */
	__u16 family;     /* AF_INET / AF_INET6 */
	__u16 sport;      /* local port, host byte order */
	__u16 dport;      /* remote port, host byte order */
	__u16 _pad;
	__u32 srtt_us;    /* smoothed RTT in µs, 0 = not sampled */
	__u32 _pad2;
};

/* Force BTF emission of the wire types: BTF only includes types reachable
 * from globals, program signatures or CO-RE relocations, and these are
 * otherwise only used by locals. The Go side depends on struct conn_event
 * being present in BTF (internal/ebpf/event_test.go). */
const enum atlas_event_type *atlas_event_type_btf __attribute__((unused));
const struct conn_event *conn_event_btf __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	/* 1 MiB: retransmit events are emitted per segment, so a lossy host
	 * shares this ring between health and lifecycle events. Overflow
	 * drops are counted, never blocking. */
	__uint(max_entries, 1 << 20);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} drop_count SEC(".maps");

static __always_inline void note_drop(void)
{
	__u32 key = 0;
	__u64 *val = bpf_map_lookup_elem(&drop_count, &key);
	if (val)
		*val += 1; /* per-cpu slot, no race */
}

static __always_inline struct conn_event *reserve_event(__u32 type)
{
	struct conn_event *e;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		note_drop();
		return 0;
	}
	__builtin_memset(e, 0, sizeof(*e));
	e->ts_ns = bpf_ktime_get_ns();
	e->type = type;
	return e;
}

/* The tcp_sock srtt estimator stores µs << 3. */
static __always_inline __u32 read_srtt_us(const void *skaddr)
{
	struct tcp_sock *tp = (struct tcp_sock *)skaddr;

	return BPF_CORE_READ(tp, srtt_us) >> 3;
}

static __always_inline void set_current_task(struct conn_event *e)
{
	e->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	bpf_get_current_comm(e->comm, sizeof(e->comm));
}

SEC("tracepoint/sock/inet_sock_set_state")
int atlas_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
	struct conn_event *e;
	__u32 type;

	if (ctx->protocol != IPPROTO_TCP)
		return 0;
	if (ctx->family != AF_INET && ctx->family != AF_INET6)
		return 0;

	switch (ctx->newstate) {
	case TCP_SYN_SENT:
		type = ATLAS_EV_OPEN;
		break;
	case TCP_ESTABLISHED:
		type = ATLAS_EV_ESTABLISHED;
		break;
	case TCP_CLOSE:
		type = ATLAS_EV_CLOSE;
		break;
	default:
		return 0;
	}

	e = reserve_event(type);
	if (!e)
		return 0;

	e->sock_id = (__u64)(unsigned long)ctx->skaddr;
	e->family = ctx->family;
	e->sport = ctx->sport; /* tracepoint stores host byte order */
	e->dport = ctx->dport;
	/* saddr_v6/daddr_v6 carry the v4-mapped form for AF_INET, so one copy
	 * covers both families. A plain memcpy compiles into loads through a
	 * modified ctx pointer, which the verifier rejects; probe_read is the
	 * sanctioned way to copy arrays out of tracepoint context. */
	bpf_probe_read_kernel(e->saddr, sizeof(e->saddr), ctx->saddr_v6);
	bpf_probe_read_kernel(e->daddr, sizeof(e->daddr), ctx->daddr_v6);

	if (type == ATLAS_EV_OPEN) {
		/* connect() runs in the owning process context. */
		set_current_task(e);
	} else if (type == ATLAS_EV_ESTABLISHED) {
		/* Fresh from the handshake: srtt holds the connect RTT. */
		e->srtt_us = read_srtt_us(ctx->skaddr);
	} else if (type == ATLAS_EV_CLOSE) {
		/* Lifetime data-octet counters (RFC 4898) from tcp_sock: unlike
		 * bytes_acked, these never count SYN/FIN sequence space.
		 * bytes_sent includes retransmitted octets. */
		struct tcp_sock *tp = (struct tcp_sock *)ctx->skaddr;

		e->bytes_sent = BPF_CORE_READ(tp, bytes_sent);
		e->bytes_recv = BPF_CORE_READ(tp, bytes_received);
		e->srtt_us = read_srtt_us(ctx->skaddr);
	}

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* One event per retransmitted segment. Correlated by socket identity;
 * the userspace side attributes it to the connection's edge. */
SEC("tracepoint/tcp/tcp_retransmit_skb")
int atlas_tcp_retransmit(struct trace_event_raw_tcp_event_sk_skb *ctx)
{
	struct conn_event *e = reserve_event(ATLAS_EV_RETRANS);

	if (!e)
		return 0;
	e->sock_id = (__u64)(unsigned long)ctx->skaddr;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* RST received by a local socket (covers refused/aborted connections
 * from this host's perspective; RSTs we send to remote peers are not
 * counted — see docs/architecture.md). */
SEC("tracepoint/tcp/tcp_receive_reset")
int atlas_tcp_receive_reset(struct trace_event_raw_tcp_event_sk *ctx)
{
	struct conn_event *e = reserve_event(ATLAS_EV_RST_RECV);

	if (!e)
		return 0;
	e->sock_id = (__u64)(unsigned long)ctx->skaddr;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("kretprobe/inet_csk_accept")
int atlas_inet_csk_accept_ret(struct pt_regs *ctx)
{
	struct sock *sk = (struct sock *)PT_REGS_RC(ctx);
	struct conn_event *e;
	__u16 family;

	if (!sk)
		return 0;

	family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (family != AF_INET && family != AF_INET6)
		return 0;

	e = reserve_event(ATLAS_EV_ACCEPT);
	if (!e)
		return 0;

	e->sock_id = (__u64)(unsigned long)sk;
	e->family = family;
	e->sport = BPF_CORE_READ(sk, __sk_common.skc_num); /* host order */
	e->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

	if (family == AF_INET) {
		__be32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
		__be32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);

		__builtin_memset(e->saddr, 0, 16);
		__builtin_memset(e->daddr, 0, 16);
		/* v4-mapped ::ffff:a.b.c.d, matching the tracepoint encoding */
		e->saddr[10] = 0xff;
		e->saddr[11] = 0xff;
		e->daddr[10] = 0xff;
		e->daddr[11] = 0xff;
		__builtin_memcpy(&e->saddr[12], &saddr, 4);
		__builtin_memcpy(&e->daddr[12], &daddr, 4);
	} else {
		BPF_CORE_READ_INTO(&e->saddr, sk,
				   __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
		BPF_CORE_READ_INTO(&e->daddr, sk,
				   __sk_common.skc_v6_daddr.in6_u.u6_addr8);
	}

	/* accept() returns in the server process context. */
	set_current_task(e);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

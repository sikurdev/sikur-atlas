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
	ATLAS_EV_OPEN = 1,         /* outbound connect initiated (has pid) */
	ATLAS_EV_ACCEPT = 2,       /* inbound connection accepted (has pid) */
	ATLAS_EV_ESTABLISHED = 3,  /* handshake completed (pid unknown, has rtt) */
	ATLAS_EV_CLOSE = 4,        /* socket closed (has bytes and rtt) */
	ATLAS_EV_RETRANS = 5,      /* one segment retransmitted (sock_id only) */
	ATLAS_EV_RST_RECV = 6,     /* RST received on a socket (sock_id only) */
	ATLAS_EV_UNIX_CONNECT = 7, /* AF_UNIX stream connect returned (has pid,
	                            * path, code=retval, sock_id=inode) */
	ATLAS_EV_EXEC = 8,         /* process exec'd (path=filename, code=old pid) */
	ATLAS_EV_EXIT = 9,         /* group leader exited (code=exit_code) */
	ATLAS_EV_OOM = 10,         /* pid chosen by the OOM killer */
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
	__s32 code;       /* EV_UNIX_CONNECT: connect retval (0 or -errno);
	                   * EV_EXIT: task exit_code; EV_EXEC: old pid */
	__u8 upath[64];   /* EV_UNIX_CONNECT: socket path (leading NUL =
	                   * abstract); EV_EXEC: executable path. Truncated. */
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

/* Scratch state between unix_stream_connect entry and return. */
struct unix_connect_args {
	__u64 inode;
	__u8 path[64];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u64);
	__type(value, struct unix_connect_args);
} unix_connects SEC(".maps");

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
 * the userspace side attributes it to the connection's edge. The raw
 * record type was renamed when the event left its event class, so the
 * program selects whichever type the running kernel's BTF carries. */
SEC("tracepoint/tcp/tcp_retransmit_skb")
int atlas_tcp_retransmit(void *ctx)
{
	struct conn_event *e;
	const void *skaddr = 0;

	if (bpf_core_type_exists(struct trace_event_raw_tcp_retransmit_skb)) {
		struct trace_event_raw_tcp_retransmit_skb *c = ctx;

		skaddr = BPF_CORE_READ(c, skaddr);
	} else {
		struct trace_event_raw_tcp_event_sk_skb *c = ctx;

		skaddr = BPF_CORE_READ(c, skaddr);
	}
	if (!skaddr)
		return 0;
	e = reserve_event(ATLAS_EV_RETRANS);
	if (!e)
		return 0;
	e->sock_id = (__u64)(unsigned long)skaddr;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ---- AF_UNIX topology ----
 *
 * unix_stream_connect(struct socket *, struct sockaddr *, int addr_len,
 * int flags) runs in the connecting process's context; the entry probe
 * captures the target path and the client socket's inode (the identity
 * sock_diag pairing uses), the return probe reports success/failure. */
SEC("kprobe/unix_stream_connect")
int atlas_unix_connect_entry(struct pt_regs *ctx)
{
	struct socket *sock = (struct socket *)PT_REGS_PARM1(ctx);
	const char *uaddr = (const char *)PT_REGS_PARM2(ctx);
	int addr_len = (int)PT_REGS_PARM3(ctx);
	struct unix_connect_args args = {};
	__u64 id = bpf_get_current_pid_tgid();
	__u32 len;

	args.inode = BPF_CORE_READ(sock, file, f_inode, i_ino);
	/* sockaddr_un: 2 bytes family, then the path (a leading NUL marks
	 * an abstract name; addr_len bounds it). */
	if (addr_len > 2) {
		len = (__u32)addr_len - 2;
		if (len > sizeof(args.path))
			len = sizeof(args.path);
		bpf_probe_read_kernel(args.path, len, uaddr + 2);
	}
	bpf_map_update_elem(&unix_connects, &id, &args, 0);
	return 0;
}

SEC("kretprobe/unix_stream_connect")
int atlas_unix_connect_ret(struct pt_regs *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct unix_connect_args *args;
	struct conn_event *e;

	args = bpf_map_lookup_elem(&unix_connects, &id);
	if (!args)
		return 0;
	e = reserve_event(ATLAS_EV_UNIX_CONNECT);
	if (e) {
		e->sock_id = args->inode;
		e->code = (__s32)PT_REGS_RC(ctx);
		__builtin_memcpy(e->upath, args->path, sizeof(e->upath));
		set_current_task(e);
		bpf_ringbuf_submit(e, 0);
	}
	bpf_map_delete_elem(&unix_connects, &id);
	return 0;
}

/* ---- process lifecycle ---- */

SEC("tracepoint/sched/sched_process_exec")
int atlas_process_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	struct conn_event *e = reserve_event(ATLAS_EV_EXEC);
	__u32 off;

	if (!e)
		return 0;
	/* Runs in the exec'ing task past the point of no return: current
	 * pid/comm are the NEW identity. */
	set_current_task(e);
	e->code = ctx->old_pid;
	off = ctx->__data_loc_filename & 0xffff;
	bpf_probe_read_kernel_str(e->upath, sizeof(e->upath), (char *)ctx + off);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int atlas_process_exit(void *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct task_struct *task;
	struct conn_event *e;

	/* Only group-leader exits: one event per process, not per thread. */
	if ((__u32)id != (__u32)(id >> 32))
		return 0;
	e = reserve_event(ATLAS_EV_EXIT);
	if (!e)
		return 0;
	set_current_task(e);
	task = (struct task_struct *)bpf_get_current_task();
	e->code = (__s32)BPF_CORE_READ(task, exit_code);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/oom/mark_victim")
int atlas_oom_victim(struct trace_event_raw_mark_victim *ctx)
{
	struct conn_event *e = reserve_event(ATLAS_EV_OOM);

	if (!e)
		return 0;
	/* Fires in the allocating task's context, NOT the victim's; only
	 * the victim pid from the record is meaningful. */
	e->pid = (__u32)ctx->pid;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* RST received by a local socket (covers refused/aborted connections
 * from this host's perspective; RSTs we send to remote peers are not
 * counted — see docs/architecture.md). tcp_receive_reset has been a
 * DEFINE_EVENT of class tcp_event_sk from 4.16 through 6.17, so its
 * record is the class record. */
SEC("tracepoint/tcp/tcp_receive_reset")
int atlas_tcp_receive_reset(struct trace_event_raw_tcp_event_sk *ctx)
{
	struct conn_event *e;
	const void *skaddr = BPF_CORE_READ(ctx, skaddr);

	if (!skaddr)
		return 0;
	e = reserve_event(ATLAS_EV_RST_RECV);
	if (!e)
		return 0;
	e->sock_id = (__u64)(unsigned long)skaddr;
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

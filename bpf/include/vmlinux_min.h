/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Minimal kernel type definitions for Sikur Atlas BPF programs.
 *
 * This is a hand-written subset of the types a generated vmlinux.h would
 * provide. Every struct that mirrors a kernel type carries
 * __attribute__((preserve_access_index)), so field accesses are CO-RE
 * relocations: libbpf/cilium-ebpf resolves the real field offsets against
 * the running kernel's BTF at load time. Only field NAMES and rough types
 * must match the kernel; offsets and omitted fields do not matter.
 *
 * Keeping this file small (instead of vendoring a 3 MB generated header)
 * makes it reviewable. If a program needs a new kernel field, add it here.
 */
#ifndef __VMLINUX_MIN_H__
#define __VMLINUX_MIN_H__

/* Signal to bpf_tracing.h that kernel-style register names (pt_regs->ax)
 * are in use, exactly as a generated vmlinux.h would. */
#ifndef __VMLINUX_H__
#define __VMLINUX_H__
#endif

typedef signed char __s8;
typedef unsigned char __u8;
typedef short __s16;
typedef unsigned short __u16;
typedef int __s32;
typedef unsigned int __u32;
typedef long long __s64;
typedef unsigned long long __u64;

typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 __be64;
typedef __u32 __wsum;

/* uapi/linux/bpf.h — only the constants we use. */
enum bpf_map_type_min {
	BPF_MAP_TYPE_PERCPU_ARRAY = 6,
	BPF_MAP_TYPE_RINGBUF = 27,
};

/* include/net/tcp_states.h */
enum tcp_state_min {
	TCP_ESTABLISHED = 1,
	TCP_SYN_SENT = 2,
	TCP_SYN_RECV = 3,
	TCP_FIN_WAIT1 = 4,
	TCP_FIN_WAIT2 = 5,
	TCP_TIME_WAIT = 6,
	TCP_CLOSE = 7,
	TCP_CLOSE_WAIT = 8,
	TCP_LAST_ACK = 9,
	TCP_LISTEN = 10,
	TCP_CLOSING = 11,
	TCP_NEW_SYN_RECV = 12,
};

#define AF_INET 2
#define AF_INET6 10
#define IPPROTO_TCP 6

/* arch/x86/include/asm/ptrace.h — layout is kernel ABI; CO-RE relocates it
 * against kernel BTF anyway thanks to preserve_access_index. */
struct pt_regs {
	unsigned long r15;
	unsigned long r14;
	unsigned long r13;
	unsigned long r12;
	unsigned long bp;
	unsigned long bx;
	unsigned long r11;
	unsigned long r10;
	unsigned long r9;
	unsigned long r8;
	unsigned long ax;
	unsigned long cx;
	unsigned long dx;
	unsigned long si;
	unsigned long di;
	unsigned long orig_ax;
	unsigned long ip;
	unsigned long cs;
	unsigned long flags;
	unsigned long sp;
	unsigned long ss;
} __attribute__((preserve_access_index));

/* include/linux/trace_events.h */
struct trace_entry {
	unsigned short type;
	unsigned char flags;
	unsigned char preempt_count;
	int pid;
} __attribute__((preserve_access_index));

/* Tracepoint record for sock:inet_sock_set_state
 * (include/trace/events/sock.h). sport/dport are host byte order;
 * saddr_v6/daddr_v6 hold the v4-mapped address for AF_INET sockets. */
struct trace_event_raw_inet_sock_set_state {
	struct trace_entry ent;
	const void *skaddr;
	int oldstate;
	int newstate;
	__u16 sport;
	__u16 dport;
	__u16 family;
	__u16 protocol;
	__u8 saddr[4];
	__u8 daddr[4];
	__u8 saddr_v6[16];
	__u8 daddr_v6[16];
} __attribute__((preserve_access_index));

struct in6_addr {
	union {
		__u8 u6_addr8[16];
	} in6_u;
} __attribute__((preserve_access_index));

/* include/net/sock.h — the kernel nests some of these fields in anonymous
 * unions; CO-RE field matching sees through that. */
struct sock_common {
	__be32 skc_daddr;
	__be32 skc_rcv_saddr;
	__be16 skc_dport;
	__u16 skc_num;
	unsigned short skc_family;
	struct in6_addr skc_v6_daddr;
	struct in6_addr skc_v6_rcv_saddr;
} __attribute__((preserve_access_index));

struct sock {
	struct sock_common __sk_common;
} __attribute__((preserve_access_index));

/* include/linux/tcp.h — lifetime data-octet counters (RFC 4898, kernel
 * >= 4.19) and the smoothed RTT estimator (µs << 3). */
struct tcp_sock {
	__u64 bytes_received;
	__u64 bytes_sent;
	__u32 srtt_us;
} __attribute__((preserve_access_index));

/* Tracepoint record shared by tcp:tcp_retransmit_skb (and siblings)
 * (include/trace/events/tcp.h, stable since 4.15). Only skaddr is read. */
struct trace_event_raw_tcp_event_sk_skb {
	struct trace_entry ent;
	const void *skbaddr;
	const void *skaddr;
} __attribute__((preserve_access_index));

/* Tracepoint record for tcp:tcp_receive_reset (stable since 4.16).
 * Deliberately NOT tcp_send_reset: its record grew a `reason` field in
 * 6.10 which shifts offsets between kernel versions. */
struct trace_event_raw_tcp_receive_reset {
	struct trace_entry ent;
	const void *skaddr;
} __attribute__((preserve_access_index));

#endif /* __VMLINUX_MIN_H__ */

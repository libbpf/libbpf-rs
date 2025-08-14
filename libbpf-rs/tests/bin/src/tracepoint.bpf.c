// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096 /* one page */);
} ringbuf SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_getpid")
int handle__tracepoint(void *ctx)
{
	int *value;

	value = bpf_ringbuf_reserve(&ringbuf, sizeof(int), 0);
	if (!value) {
		bpf_printk(
			"handle__tracepoint: failed to reserve ring buffer space");
		return 1;
	}

	*value = 1;
	bpf_ringbuf_submit(value, 0);
	bpf_printk("handle__tracepoint: submitted ringbuf value");
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_getpid")
int handle__tracepoint_with_cookie(void *ctx)
{
	int *value;

	value = bpf_ringbuf_reserve(&ringbuf, sizeof(int), 0);
	if (!value) {
		bpf_printk(
			"handle__tracepoint_with_cookie: failed to reserve ring buffer space");
		return 1;
	}

	*value = bpf_get_attach_cookie(ctx);
	bpf_printk("handle__tracepoint_with_cookie: cookie=%d", *value);
	bpf_ringbuf_submit(value, 0);
	return 0;
}

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__type(key, int);
	__type(value, int);
} pb SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_getpid")
int handle__tracepoint_with_cookie_pb(void *ctx)
{
	int value = bpf_get_attach_cookie(ctx);
	bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, &value,
			      sizeof(value));

	return 0;
}

struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, 10);
	__uint(key, 0);
	__type(value, __u32);
} queue SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK);
	__uint(max_entries, 10);
	__uint(key, 0);
	__type(value, __u32);
} stack SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_BLOOM_FILTER);
	__uint(max_entries, 5);
	__type(value, __u32);
} bloom_filter SEC(".maps");

char LICENSE[] SEC("license") = "GPL";

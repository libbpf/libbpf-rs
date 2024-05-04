// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2024 Jose Fernandez

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
	__uint(type, BPF_MAP_TYPE_USER_RINGBUF);
	__uint(max_entries, 4096 /* one page */);
} user_ringbuf SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 100);
} samples SEC(".maps");

struct my_struct_t {
	u32 key;
	u32 value;
};

static long user_ringbuf_callback(struct bpf_dynptr *dynptr, void *context)
{
	const struct my_struct_t *data;

	data = bpf_dynptr_data(dynptr, 0, sizeof(*data));
	if (!data)
		return 0;

	bpf_map_update_elem(&samples, &data->key, &data->value, BPF_ANY);

	return 0;
}

SEC("tp/syscalls/sys_enter_getpid")
int handle__sys_enter_getpid(void *ctx)
{
	bpf_user_ringbuf_drain(&user_ringbuf, user_ringbuf_callback, NULL, 0);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";

// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021. Huawei Technologies Co., Ltd */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, 1);
} test_counter_map SEC(".maps");

SEC("struct_ops/test_1")
int BPF_PROG(test_1, struct bpf_dummy_ops_state *state)
{
	int ret;

	if (!state)
		return 0xf2f3f4f5;

	ret = state->val;
	state->val = 0x5a;
	return ret;
}

__u64 test_2_args[5];

SEC("struct_ops/test_2")
int BPF_PROG(test_2, struct bpf_dummy_ops_state *state, int a1,
	     unsigned short a2, char a3, unsigned long a4)
{
	test_2_args[0] = (unsigned long)state;
	test_2_args[1] = a1;
	test_2_args[2] = a2;
	test_2_args[3] = a3;
	test_2_args[4] = a4;
	return 0;
}

SEC("xdp")
int xdp_counter(struct xdp_md *ctx)
{
	u32 key = 0;
	u32 *value = bpf_map_lookup_elem(&test_counter_map, &key);
	if (value) {
		*value += 1;
		return XDP_PASS;
	}
	return XDP_DROP;
}

SEC(".struct_ops")
struct bpf_dummy_ops dummy_1 = {
	.test_1 = (void *)test_1,
	.test_2 = (void *)test_2,
};

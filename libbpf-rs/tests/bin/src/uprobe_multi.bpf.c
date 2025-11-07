// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 2);
	__type(key, int);
	__type(value, int);
} hash_map SEC(".maps");

SEC("uprobe.multi")
int handle__uprobe_multi(void *ctx)
{
	const int key = 0, init_val = 1;

	int *val = bpf_map_lookup_elem(&hash_map, &key);
	if (val) {
		__sync_fetch_and_add(val, 1);
		bpf_printk("handle__uprobe_multi: val=%d\n", *val);
	} else {
		bpf_map_update_elem(&hash_map, &key, &init_val, BPF_ANY);
	}

	return 0;
}

SEC("uprobe.multi")
int handle__uprobe_multi_with_opts(void *ctx)
{
	const int key = 1, init_val = 1;

	int *val = bpf_map_lookup_elem(&hash_map, &key);
	if (val) {
		__sync_fetch_and_add(val, 1);
		bpf_printk("handle__uprobe_multi_with_opts: val=%d\n", *val);
	} else {
		bpf_map_update_elem(&hash_map, &key, &init_val, BPF_ANY);
	}
	
	return 0;
}

char LICENSE[] SEC("license") = "GPL";

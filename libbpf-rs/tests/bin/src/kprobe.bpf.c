// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("kprobe/bpf_fentry_test1")
int handle__kprobe(void *ctx)
{
	return 0;
}

char LICENSE[] SEC("license") = "GPL";

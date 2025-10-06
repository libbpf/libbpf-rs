// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_tracing.h>

SEC("perf_event")
int handle__perf_event(void *ctx)
{
	return 0;
}

char LICENSE[] SEC("license") = "GPL";

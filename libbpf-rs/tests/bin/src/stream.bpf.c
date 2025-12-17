// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

/*
 * Trigger writing of some messages to stdout & stderr streams.
 */
SEC("syscall")
int trigger_streams(void *ctx)
{
    bpf_stream_printk(1, "stdout");
    bpf_stream_printk(2, "stderr");
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

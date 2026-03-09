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
    unsigned long long args[1] = {};

    bpf_stream_vprintk_impl(1, "stdout", args, 0, NULL);
    bpf_stream_vprintk_impl(2, "stderr", args, 0, NULL);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

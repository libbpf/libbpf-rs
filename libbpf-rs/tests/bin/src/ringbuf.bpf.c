// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 William Findlay
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096 /* one page */);
} ringbuf1 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096 /* one page */);
} ringbuf2 SEC(".maps");

SEC("tp/syscalls/sys_enter_getpid")
int handle__sys_enter_getpid(void *ctx)
{
    int *value;

    value = bpf_ringbuf_reserve(&ringbuf1, sizeof(int), 0);
    if (value) {
        *value = 1;
        bpf_ringbuf_submit(value, 0);
    }

    value = bpf_ringbuf_reserve(&ringbuf2, sizeof(int), 0);
    if (value) {
        *value = 2;
        bpf_ringbuf_submit(value, 0);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";

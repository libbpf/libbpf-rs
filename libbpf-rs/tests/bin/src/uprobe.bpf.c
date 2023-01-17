// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/usdt.bpf.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096 /* one page */);
} ringbuf SEC(".maps");

SEC("uprobe")
int handle__uprobe(void *ctx)
{
    int *value;

    value = bpf_ringbuf_reserve(&ringbuf, sizeof(int), 0);
    if (value) {
        *value = 1;
        bpf_ringbuf_submit(value, 0);
    }

    return 0;
}

SEC("uprobe")
int handle__uprobe_with_cookie(void *ctx)
{
    int *value;

    value = bpf_ringbuf_reserve(&ringbuf, sizeof(int), 0);
    if (value) {
        *value = bpf_get_attach_cookie(ctx);
        bpf_ringbuf_submit(value, 0);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";

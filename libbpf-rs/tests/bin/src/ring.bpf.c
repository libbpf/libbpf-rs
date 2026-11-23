// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096 /* one page */);
} ring SEC(".maps");

/* Only system calls made by this thread write a record. */
const volatile __u32 target_tid;

/* Sequence number of the next record. */
__u64 seq;

SEC("tp/syscalls/sys_enter_getppid")
int handle__sys_enter_getppid(void *ctx)
{
    __u64 *value;

    if ((__u32)bpf_get_current_pid_tgid() != target_tid)
        return 0;

    value = bpf_ringbuf_reserve(&ring, sizeof(*value), 0);
    if (value) {
        *value = seq++;
        bpf_ringbuf_submit(value, 0);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";

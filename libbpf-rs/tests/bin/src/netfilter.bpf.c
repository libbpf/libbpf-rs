#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define NF_ACCEPT 1

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096 /* one page */);
} ringbuf SEC(".maps");

SEC("netfilter")
int handle_netfilter(struct bpf_nf_ctx *ctx) {

    int *value;

    value = bpf_ringbuf_reserve(&ringbuf, sizeof(int), 0);
    if (!value) {
        bpf_printk("handle_netfilter: failed to reserve ring buffer space");
        return 1;
    }

    *value = 1;
    bpf_ringbuf_submit(value, 0);

    bpf_printk("handle_netfilter: submitted ringbuf value");
    return NF_ACCEPT;
}

char LICENSE[] SEC("license") = "GPL";

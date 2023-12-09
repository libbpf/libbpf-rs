#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
    return XDP_PASS;
}
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define NF_DROP 0
#define NF_ACCEPT 1

int bpf_dynptr_from_skb(struct sk_buff *skb,
    __u64 flags, struct bpf_dynptr *ptr__uninit) __ksym;
void *bpf_dynptr_slice(const struct bpf_dynptr *ptr,
    uint32_t offset, void *buffer, uint32_t buffer__sz) __ksym;


struct lpm_key {
    __u32 prefixlen;
    __be32 addr;
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_key);
    __type(value, __u32);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, 200);
} block_ips SEC(".maps");

SEC("netfilter")
int netfilter_local_in(struct bpf_nf_ctx *ctx) {

    struct sk_buff *skb = ctx->skb;
    struct bpf_dynptr ptr;
    struct iphdr *p, iph = {};
    struct lpm_key key;
    __u32 *match_value;

    if (skb->len <= 20 || bpf_dynptr_from_skb(skb, 0, &ptr))
        return NF_ACCEPT;
    p = bpf_dynptr_slice(&ptr, 0, &iph, sizeof(iph));
    if (!p)
        return NF_ACCEPT;

    /* ip4 only */
    if (p->version != 4)
        return NF_ACCEPT;

    /* search p->daddr in trie */
    key.prefixlen = 32;
    key.addr = p->daddr;
    match_value = bpf_map_lookup_elem(&block_ips, &key);
    if (match_value) {
        /* To view log output, use: cat /sys/kernel/debug/tracing/trace_pipe */
        __be32 addr_host = bpf_ntohl(key.addr);
        bpf_printk("Blocked IP: %d.%d.%d.%d, prefix length: %d, map value: %d\n",
           (addr_host >> 24) & 0xFF, (addr_host >> 16) & 0xFF,
           (addr_host >> 8) & 0xFF, addr_host & 0xFF,
           key.prefixlen, *match_value);
        return NF_DROP;
    }
    return NF_ACCEPT;
}

char _license[] SEC("license") = "GPL";

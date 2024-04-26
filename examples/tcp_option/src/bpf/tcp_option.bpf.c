// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define IP_MF 0x2000
#define IP_OFFSET 0x1FFF
#define ETH_HLEN 14
#define ETH_P_IP 0x0800

#define TCP_OPTION_CODE 253
#define TCP_OPTION_MAGIC 0xEB9F

char _license[] SEC("license") = "GPL";

const volatile __u32 targ_ip = 0;
const volatile __u32 data_such_as_trace_id = 0;

struct __attribute__((packed)) tcp_option
{
    u8 kind;
    u8 length;
    u16 magic;
    u32 data;
};

static void reserve_space_for_tcp_option(struct bpf_sock_ops *skops)
{
    u32 need_space = skops->skb_len + sizeof(struct tcp_option);
    if (need_space > skops->mss_cache)
        return;

    bpf_printk("Sufficient space available to store a TCP option, total space: %u, required space: %u", skops->mss_cache, need_space);
    bpf_reserve_hdr_opt(skops, sizeof(struct tcp_option), 0);
}

static inline void store_tcp_option_header(struct bpf_sock_ops *skops)
{
    struct tcp_option tcp_option;
    struct tcphdr *th = skops->skb_data;

    if (skops->skb_len + sizeof(struct tcp_option) > skops->mss_cache)
        return;

    tcp_option.kind = TCP_OPTION_CODE;
    tcp_option.length = sizeof(struct tcp_option);
    tcp_option.magic = bpf_htons(TCP_OPTION_MAGIC);
    tcp_option.data = data_such_as_trace_id;
    bpf_store_hdr_opt(skops, &tcp_option, sizeof(tcp_option), 0);
    bpf_printk("Stored a TCP option in TCP Flag: %u", skops->skb_tcp_flags);
}

SEC("sockops")
int sockops_write_tcp_options(struct bpf_sock_ops *skops)
{
    u32 l_ip, r_ip;
    l_ip = skops->local_ip4;
    r_ip = skops->remote_ip4;

    // Check if the IP addresses match the target IP
    if (r_ip != targ_ip && l_ip != targ_ip) {
        return 1;
    }
    switch (skops->op)
    {
    // When creating a connection to another host
    case BPF_SOCK_OPS_TCP_CONNECT_CB:
        bpf_sock_ops_cb_flags_set(skops, skops->bpf_sock_ops_cb_flags | BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG);
        break;
    // When accepting a connection from another host
    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
        bpf_sock_ops_cb_flags_set(skops, skops->bpf_sock_ops_cb_flags | BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG);
        break;
    // When the socket is established
    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
        bpf_sock_ops_cb_flags_set(skops, skops->bpf_sock_ops_cb_flags | BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG);
        break;
    // When reserving space for TCP options header
    case BPF_SOCK_OPS_HDR_OPT_LEN_CB:
        reserve_space_for_tcp_option(skops);
        break;
    // When writing TCP options header
    case BPF_SOCK_OPS_WRITE_HDR_OPT_CB:
        store_tcp_option_header(skops);
        break;
    }
    return 1;
}

struct __tcphdr
{
    __be16 source;
    __be16 dest;
    __be32 seq;
    __be32 ack_seq;
    __u16 res1 : 4, doff : 4, fin : 1, syn : 1, rst : 1, psh : 1, ack : 1, urg : 1, ece : 1, cwr : 1;
    __be16 window;
    __sum16 check;
    __be16 urg_ptr;
};

static inline int ip_is_fragment(struct __sk_buff *skb, __u32 nhoff)
{
    __u16 frag_off;

    bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, frag_off), &frag_off, 2);
    frag_off = __bpf_ntohs(frag_off);
    return frag_off & (IP_MF | IP_OFFSET);
}

SEC("socket")
int socket_handler(struct __sk_buff *skb) {
    u16 proto;
    u32 nhoff = ETH_HLEN;
    u8 hdr_len;
    u32 tcp_hdr_start = 0;
    u32 ip_proto = 0;
    u32 l_ip, r_ip;
    bpf_skb_load_bytes(skb, 12, &proto, 2);
    proto = __bpf_ntohs(proto);
    if (proto != ETH_P_IP)
        return 0;
    
    if (ip_is_fragment(skb, nhoff))
        return 0;

    bpf_skb_load_bytes(skb, ETH_HLEN, &hdr_len, sizeof(hdr_len));
    hdr_len &= 0x0f;
    hdr_len *= 4;


    bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, protocol), &ip_proto, 1);

    if (ip_proto != IPPROTO_TCP)
    {
        return 0;
    }

    bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, saddr), &l_ip, 4);
    bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, daddr), &r_ip, 4);

    if (r_ip == targ_ip || l_ip == targ_ip) {

        tcp_hdr_start = nhoff + hdr_len;
        u8 tcp_flag;
        bpf_skb_load_bytes(skb, tcp_hdr_start + offsetof(struct __tcphdr, ack_seq) + 5, &tcp_flag, sizeof(tcp_flag));
    
        u16 tcp_data_offset;
        bpf_skb_load_bytes(skb, tcp_hdr_start + offsetof(struct __tcphdr, ack_seq) + 4, &tcp_data_offset, sizeof(tcp_data_offset));

        tcp_data_offset = __bpf_ntohs(tcp_data_offset) >> 12;
        tcp_data_offset *= 4;

        u32 option_start = tcp_hdr_start + 20;
        u32 option_end = tcp_hdr_start + tcp_data_offset;
        int i = 0;
        for (i = 0; i < 10; i++) {
            u16 option_hdr;
            bpf_skb_load_bytes(skb, option_start, &option_hdr, sizeof(option_hdr));
            u8 length  = option_hdr>>8;
            u8 kind  = option_hdr & 0xff;

            if (kind == 1) {
                option_start += 1;
                goto END;
            }

            if (kind == TCP_OPTION_CODE) {
                u16 magic;
                u32 data;
                
                // Load magic number from TCP option header
                bpf_skb_load_bytes(skb, option_start + 2, &magic, sizeof(magic));
                magic = __bpf_ntohs(magic);
                bpf_printk("####=> Socket TCP option magic: 0x%x", magic);

                if (magic == TCP_OPTION_MAGIC) {
                    // Load data from TCP option header
                    bpf_skb_load_bytes(skb, option_start + 4, &data, sizeof(data));
                    bpf_printk("####=> Socket TCP option data: %u", data);
                }
            }

            option_start += length;
            END:
            if (option_start >= option_end) {
                break;
            }
        }

    }
    return skb->len;
}

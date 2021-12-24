#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

//#include <linux/if_ether.h>
#define ETH_P_IP    0x0800
#define ETH_P_IPV6  0x86DD

//#include <linux/pkt_cls.h>
#define TC_ACT_UNSPEC	(-1)
#define TC_ACT_SHOT		2

u8 rc_allow = TC_ACT_UNSPEC;
u8 rc_disallow = TC_ACT_SHOT;

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 10);
    __type(value, u16);
    __type(key, u32);
} ports SEC(".maps");

/*
 * Allow a port if it is on the allow_ports map
 *
 * @param port, value of incoming (ingress case) or outgoing (egress case)
 *        port in network byte order
 *
 * @return true if port is on the allow_ports list
 *         false otherwise
 */
static bool allow_port(__be16 port)
{
    u16 hport = bpf_ntohs(port);
    u32 i = 0;
    for (i = 0; i < 10; i++) {
        u32 key = i;
        u16 *allow_port = bpf_map_lookup_elem(&ports, &key);
        if (allow_port && hport == *allow_port) {
            return true;
        }
    }

    return false;
}

/*
 * handle TC hook program
 *
 * @param - skb - the bpf socket buffer mirror
 * @param - rc_allow - Action to take if this packet is on the allow_ports list
 *          (see TC_ACT_* values in pkt_cls.h)
 * @param - rc_disallow - Action to take if this packet is not on the allow_ports list
 *          (see TC_ACT_* values in pkt_cls.h)
 * 
 * @return - returns value from rc_disallow if this packet is tcp/ip or udp/ip
 *           and not on an allowed port
 *           returns value from rc_allow if this is a tcp/ip udp/ip packet and port
 *           is on the allow_ports list
 *           returns TC_ACT_UNSPEC (keep processing packet in TC chain) if this
 *           packet is not tcp/ip or udp/ip
 */
SEC("tc")
int handle_tc(struct __sk_buff *skb)
{
    // default drop packets
    int rc = rc_disallow; 

    void *data_end = (void*)(long)skb->data_end;
    struct ethhdr *eth = (struct ethhdr*)(void*)(long)skb->data;

    __be16 dst = 0;
    __be16 src = 0;
    __be16 port = 0;
    __u8 proto = 0;

    void *trans_data;
    if (eth + 1 > data_end) {
        return TC_ACT_UNSPEC;
    }

    if (eth->h_proto == bpf_htons(ETH_P_IP)) { // ipv4
        struct iphdr *iph = (struct iphdr *)((void*)eth + sizeof(*eth));
        if ((void*)(iph + 1) > data_end) {
           return TC_ACT_SHOT;
        }

        proto = iph->protocol;
        trans_data = (void*)iph + (iph->ihl * 4);
    } else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) { // ipv6
        struct ipv6hdr *ip6h = (struct ipv6hdr *)((void*)eth + sizeof(*eth));
        if ((void*)(ip6h + 1) > data_end) {
           return TC_ACT_SHOT;
        }

        proto = ip6h->nexthdr;
        trans_data = ip6h + 1;
    }

    if (proto == IPPROTO_TCP)  {
        struct tcphdr *tcph = (struct tcphdr *)trans_data;
        
        if ((void*)(trans_data + sizeof(*tcph)) > data_end) {
            return TC_ACT_SHOT;
        }

        dst = tcph->dest;
        src = tcph->source;
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *udph = (struct udphdr *)trans_data;
        if ((void*)(trans_data + sizeof(*udph)) > data_end) {
            return TC_ACT_SHOT;
        }

        dst = udph->dest;
        src = udph->source;
    } else {
        goto found_unknown;
    }

    if (allow_port(src) || allow_port(dst)) {
        rc = rc_allow; 
    }

    if (skb->ingress_ifindex) {
        bpf_printk("b ingress on -- src %d dst %d",
            bpf_ntohs(src), bpf_ntohs(dst));
    } else {
        bpf_printk("b  egress on -- src %d dst %d",
            bpf_ntohs(src), bpf_ntohs(dst));
    }
        
    return rc;
found_unknown:
    rc = TC_ACT_UNSPEC;
    return rc;
}

char _license[] SEC("license") = "GPL";

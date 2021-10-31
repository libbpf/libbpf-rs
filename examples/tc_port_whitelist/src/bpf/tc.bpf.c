#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

//#include <linux/if_ether.h>
#define ETH_P_IP    0x0800
#define ETH_P_IPV6  0x86DD

//#include <linux/pkt_cls.h>
#define TC_ACT_UNSPEC	(-1)
#define TC_ACT_OK		0
#define TC_ACT_RECLASSIFY	1
#define TC_ACT_SHOT		2
#define TC_ACT_PIPE		3
#define TC_ACT_STOLEN		4
#define TC_ACT_QUEUED		5
#define TC_ACT_REPEAT		6
#define TC_ACT_REDIRECT		7
#define TC_ACT_TRAP		8

u8 rc_allow = TC_ACT_UNSPEC;
u8 rc_disallow = TC_ACT_SHOT;

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 10);
    __type(value, u16);
    __type(key, u32);
} ports SEC(".maps");

/*
 * Determine an ip4 header
 *
 * @param eth, ethernet header
 * @param data_end, end of the entire packet
 *
 * @return a struct iphdr if this is an ipv4 packet
 *         NULL otherwise
 */
static struct iphdr* is_ipv4(struct ethhdr *eth, void *data_end) 
{
    struct iphdr *iph = NULL;
    if (!eth || !data_end) {
        return NULL;
    }

    if ((void*)eth + sizeof(*eth) + sizeof(*iph) > data_end) {
        return NULL;
    }
    
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        iph = (struct iphdr*)((void*)eth + sizeof(*eth));
    }
    return iph;
}

/*
 * Determine an ip6 header
 *
 * @param eth, ethernet header
 * @param data_end, end of the entire packet
 *
 * @return a struct ipv6hdr if this is an ipv6 packet
 *         NULL otherwise
 */
struct ipv6hdr* is_ipv6(struct ethhdr *eth, void *data_end) 
{
    struct ipv6hdr *iph = NULL;
    if (!eth || !data_end) {
        return NULL;
    }

    if ((void*)eth + sizeof(*eth) + sizeof(*iph) > data_end) {
        return NULL;
    }
    
    if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        iph = (struct ipv6hdr*)((void*)eth + sizeof(*eth));
    }
    return iph;
}

/*
 * Determine udp header 
 *
 * @param iph, iphdr or ipv6hdr depending on hdr_size
 * @param hdr_sz, size of the iph.
 *        valid values are either sizeof(struct iphdr) or sizeof(ipv6hdr)
 * @param data_end, end of the entire packet
 *
 * @return a struct udphdr if this is an udp packet
 *         NULL otherwise
 */
struct udphdr* is_udp(void *iph, u8 hdr_sz, void *data_end)
{
    struct udphdr *udph = NULL;
    if (!iph || !data_end) {
        return NULL;
    }

    if ((void*)(iph + hdr_sz + sizeof(*udph)) > data_end) {
        return NULL;
    }

    int proto = -1;
    if (hdr_sz == sizeof(struct iphdr)) {
        struct iphdr *v4 = (struct iphdr*)iph;
        proto = v4->protocol;
    } else if (hdr_sz == sizeof(struct ipv6hdr)) {
        struct ipv6hdr *v6 = (struct ipv6hdr*)iph;
        proto = v6->nexthdr;
    }

    if (proto == IPPROTO_UDP) {
        udph = (struct udphdr*)((void*)iph + hdr_sz);
    }
    return udph; 
}

/*
 * Determine tcp header 
 *
 * @param iph, iphdr or ipv6hdr depending on hdr_size
 * @param hdr_sz, size of the iph.
 *        valid values are either sizeof(struct iphdr) or sizeof(ipv6hdr)
 * @param data_end, end of the entire packet
 *
 * @return a struct tcphdr if this is a tcp packet
 *         NULL otherwise
 */
struct tcphdr* is_tcp(void *iph, u8 hdr_sz, void *data_end)
{
    struct tcphdr *tcph = NULL;
    if (!iph || !data_end) {
        return NULL;
    }

    if ((void*)(iph + hdr_sz + sizeof(*tcph)) > data_end) {
        return NULL;
    }

    int proto = -1;
    if (hdr_sz == sizeof(struct iphdr)) {
        struct iphdr *v4 = (struct iphdr*)iph;
        proto = v4->protocol;
    } else if (hdr_sz == sizeof(struct ipv6hdr)) {
        struct ipv6hdr *v6 = (struct ipv6hdr*)iph;
        proto = v6->nexthdr;
    }

    if (proto == IPPROTO_TCP) {
        tcph = (struct tcphdr*)((void*)iph + hdr_sz);
    }
    return tcph;
}

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
SEC("classifier")
int handle_tc(struct __sk_buff *skb)
{
    // default drop packets
    int rc = rc_disallow; 

    void *data_end = (void*)(long)skb->data_end;
    struct ethhdr *eth = (struct ethhdr*)(void*)(long)skb->data;
    struct iphdr *iph = is_ipv4(eth, data_end);
    struct ipv6hdr *iph6 = is_ipv6(eth, data_end);

    struct udphdr *udph = NULL;
    struct tcphdr *tcph = NULL;
    __be16 dst = 0;
    __be16 src = 0;
    __be16 port = 0;
    // IPv4 packet
    if (iph) {
        u8 hdr_sz = sizeof(*iph);
        udph = is_udp(iph, hdr_sz, data_end);
        tcph = is_tcp(iph, hdr_sz, data_end);
    } else if (iph6) { // IPv6 packet
        u8 hdr_sz = sizeof(*iph6);
        udph = is_udp(iph6, hdr_sz, data_end);
        tcph = is_tcp(iph6, hdr_sz, data_end);
    }

    // if both NULL then this was not IPvX/TCP or UDP -- allow
    if (!udph && !tcph) {
        goto allow_unknown;
    }

    if (tcph) {
        dst = tcph->dest;
        src = tcph->source;
    } else if (udph) {
        dst = udph->dest;
        src = udph->source;
    }

    if (allow_port(src) || allow_port(dst)) {
        rc = rc_allow; 
    } else if (skb->ingress_ifindex) {
        bpf_printk("b ingress on -- src %d dst %d\n",
            bpf_ntohs(src), bpf_ntohs(dst));
    } else {
        bpf_printk("b  egress on -- src %d dst %d\n",
            bpf_ntohs(src), bpf_ntohs(dst));
    }
        
    return rc;
allow_unknown:
    rc = TC_ACT_UNSPEC;
    return rc;
}

char _license[] SEC("license") = "GPL";

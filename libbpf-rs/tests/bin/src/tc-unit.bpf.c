#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

//#include <linux/pkt_cls.h>
#define TC_ACT_UNSPEC	(-1)

SEC("tc")
int handle_tc(struct __sk_buff *skb)
{
    return TC_ACT_UNSPEC;
}


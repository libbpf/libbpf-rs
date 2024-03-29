// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

int ca_cnt = 0;
bool cong_control = false;

static inline struct tcp_sock *tcp_sk(const struct sock *sk)
{
	return (struct tcp_sock *)sk;
}

SEC("struct_ops/ca_update_init")
void BPF_PROG(ca_update_init, struct sock *sk)
{
	ca_cnt++;
}

SEC("struct_ops/ca_update_2_init")
void BPF_PROG(ca_update_2_init, struct sock *sk)
{
}

SEC("struct_ops/ca_update_cong_control")
void BPF_PROG(ca_update_cong_control, struct sock *sk,
	      const struct rate_sample *rs)
{
}

SEC("struct_ops/ca_update_cong_control2")
void BPF_PROG(ca_update_cong_control2, struct sock *sk,
	      const struct rate_sample *rs)
{
  cong_control = true;
}

SEC("struct_ops/ca_update_ssthresh")
__u32 BPF_PROG(ca_update_ssthresh, struct sock *sk)
{
	return tcp_sk(sk)->snd_ssthresh;
}

SEC("struct_ops/ca_update_undo_cwnd")
__u32 BPF_PROG(ca_update_undo_cwnd, struct sock *sk)
{
	return tcp_sk(sk)->snd_cwnd;
}

SEC(".struct_ops.link")
struct tcp_congestion_ops ca_update = {
	.init = (void *)ca_update_init,
	.cong_control = (void *)ca_update_cong_control,
	.ssthresh = (void *)ca_update_ssthresh,
	.undo_cwnd = (void *)ca_update_undo_cwnd,
	.name = "tcp_ca_update",
};

SEC(".struct_ops")
struct tcp_congestion_ops ca_update_2 = {
	.init = (void *)ca_update_2_init,
	.cong_control = (void *)ca_update_cong_control2,
	.ssthresh = (void *)ca_update_ssthresh,
	.undo_cwnd = (void *)ca_update_undo_cwnd,
	.name = "tcp_ca_update_2",
};

SEC(".struct_ops.link")
struct tcp_congestion_ops ca_wrong = {
	.cong_control = (void *)ca_update_cong_control,
};

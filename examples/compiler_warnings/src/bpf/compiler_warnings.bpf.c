// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

__attribute__((deprecated("can't-touch-this"))) void thefloorislava() {
  bpf_printk("ouch");
}

SEC("tracepoint/syscalls/sys_enter_getpid")
int handle__tracepoint(void *ctx) {
  thefloorislava();
  return 0;
}

char _license[] SEC("license") = "GPL";

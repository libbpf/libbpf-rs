#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, 1);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} auto_pin_map SEC(".maps");

u64 resizable_data[1] SEC(".data.resizable_data");

char _license[] SEC("license") = "GPL";

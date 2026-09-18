// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

/* Globals tagged with this end up in the `.addr_space.1` section, which
 * libbpf copies into the arena at load time.
 */
#define __arena __attribute__((address_space(1)))

struct {
    __uint(type, BPF_MAP_TYPE_ARENA);
    __uint(map_flags, BPF_F_MMAPABLE);
    /* Number of pages. */
    __uint(max_entries, 100);
    /* Start of the mmap'ed region. */
    __ulong(map_extra, 1ull << 44);
} arena SEC(".maps");

int __arena counter;
long __arena sum;

SEC("syscall")
int bump_arena_globals(void *ctx)
{
    counter += 1;
    sum += 10;
    return 0;
}

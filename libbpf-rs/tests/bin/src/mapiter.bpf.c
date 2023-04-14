#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

SEC("iter/bpf_map_elem")
int map_iter(struct bpf_iter__bpf_map_elem *ctx) {
  struct seq_file *seq = ctx->meta->seq;
  __u32 seq_num = ctx->meta->seq_num;
  struct bpf_map *map = ctx->map;
  __u32 *key = ctx->key;
  __u64 *value = ctx->value;
  __u32 tmp_key = 0;
  __u64 tmp_val = 0;

  if (seq_num == 0) {
    bpf_printk("map dump starts");
  }

  if (key == (void *)0 || value == (void *)0) {
    bpf_printk("map dump end");
    return 0;
  }

  bpf_printk("test map iter, target map: %s, key: %d", map->name, (*key));
  bpf_seq_write(seq, key, sizeof(__u32));
  return 0;
}

char _license[] SEC("license") = "GPL";

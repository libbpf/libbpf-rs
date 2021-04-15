#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

struct index_pid_pair {
  uint32_t i;
  pid_t pid;
};

static uint32_t i = 0;

SEC("iter/task")
int dump_pid(struct bpf_iter__task *ctx)
{
  struct seq_file *seq = ctx->meta->seq;
  struct task_struct *task = ctx->task;
  struct index_pid_pair p;

  if (!task)
    return 0;

  p.i = i++;
  p.pid = task->tgid;

  bpf_seq_write(seq, &p, sizeof(p));
  return 0;
}

char _license[] SEC("license") = "GPL";


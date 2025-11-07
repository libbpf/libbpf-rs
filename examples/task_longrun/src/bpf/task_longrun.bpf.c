#include "vmlinux.h"
#include "task_longrun.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

// Dummy instance to get skeleton to generate definition for `struct event`
struct event _event = {0};

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __type(key, u32);
    /* bpflint: disable=untyped-map-member */
    __uint(value_size, PERF_MAX_STACK_DEPTH * sizeof(u64));
    __uint(max_entries, __NR_STACKS__);
} stacks SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct running_task);
    __uint(max_entries, 1);
} running_tasks SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __type(key, u32);
    __type(value, u32);
} events SEC(".maps");

SEC("tp_btf/sched_switch")
int handle__sched_switch(u64 *ctx)
{
    // TP_PROTO(bool preempt, struct task_struct *prev, struct task_struct
    // *next, struct rq_flags *rf)
    struct task_struct *prev = (struct task_struct *)ctx[1];
    struct task_struct *next = (struct task_struct *)ctx[2];
    s32 cpu = bpf_get_smp_processor_id();
    u64 now = bpf_ktime_get_ns();
    struct running_task *t;
    if (!(t = bpf_map_lookup_elem(&running_tasks, &cpu)))
        return 0;
    if (t->running_at && prev->pid) {
        s64 dur = now - t->running_at;
        if (dur > runtime_thresh_ns) {
            struct event event = {0};
            bpf_probe_read_kernel(event.comm, TASK_COMM_LEN, prev->comm);
            bpf_probe_read_kernel(event.bt, sizeof(t->bt), t->bt);
            event.pid = prev->pid;
            event.duration = dur;
            event.bt_sample_cnt = t->bt_sample_cnt;
            bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event,
                                  sizeof(event));
        }
    }
    t->running_at = 0;
    t->bt_at = 0;
    if (kthread_only && !(next->flags & PF_KTHREAD))
        return 0;
    if (percpu_only && next->nr_cpus_allowed != 1)
        return 0;
    t->running_at = now;
    t->bt_at = now;
    t->bt_sample_cnt = 0;
    return 0;
}

/* bpflint: disable=unstable-attach-point */
SEC("kprobe/scheduler_tick")
void handle__sched_tick(struct pt_regs *ctx)
{
    s32 cpu = bpf_get_smp_processor_id();
    u64 now = bpf_ktime_get_ns();
    struct running_task *t;
    u32 stkid, idx;
    if (!(t = bpf_map_lookup_elem(&running_tasks, &cpu)))
        return;
    if (!t->bt_at || now - t->bt_at < backtrace_interval_ns)
        return;

    idx = t->bt_sample_cnt++ % __NR_BTS__;
    t->bt[idx] = bpf_get_stackid(ctx, &stacks, BPF_F_REUSE_STACKID);
    t->bt_at = now;
}

char _license[] SEC("license") = "GPL";

/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __TASK_LONGRUN_H__
#define __TASK_LONGRUN_H__

#define __NR_STACKS__           32768
#define __NR_BTS__              64
#define PERF_MAX_STACK_DEPTH    127
#define PF_KTHREAD        0x00200000
#define TASK_COMM_LEN           16

const volatile u64 runtime_thresh_ns = 0;
const volatile u64 backtrace_interval_ns = 0;
const volatile bool kthread_only = false;
const volatile bool percpu_only = false;

struct running_task {
    u64             running_at;
    u64             bt_at;
    u32             bt[__NR_BTS__];
    u32             bt_sample_cnt;
    pid_t           pid;
    u8            comm[TASK_COMM_LEN];
    u64             ran_for;
};

struct event {
    u8              comm[TASK_COMM_LEN];
    pid_t           pid;
    u32             bt_sample_cnt;
    u64             duration;
    u32             bt[__NR_BTS__];
};

#endif  /* __TASK_LONGRUN_H__ */

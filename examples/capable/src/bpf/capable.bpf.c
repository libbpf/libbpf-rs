// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 BMC Software, Inc.
// Author Devasia Thomas <https://www.linkedin.com/in/devasiathomas/>

#include "vmlinux.h"
#include "capable.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

extern int LINUX_KERNEL_VERSION __kconfig;

const volatile struct {
    gid_t tgid; //PID to filter
    bool verbose; // Include non audit logs
    bool k_stacks; // Include kernel stacks to trace
    bool u_stacks; // Include user stacks to trace
    enum Unique unique_type; // Only Unique stack traces for same pid or cgroup
    //bool only_mnt_ns; // Only trace Unique mnt ns
    bool cap_opts; // linux >= v5.1 check for insetid

} tool_config = {0};


struct event _event = {0}; //Dummy instance for skeleton to generate definition

struct unique_stack_key {
    int cap;
    u32 tgid;
    u64 cgroupid;
    int kernel_stack_id;
    int user_stack_id;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events
SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct unique_stack_key);
    __type(value, u64);
} seen
SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, 2048);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u64)*BPF_MAX_STACK_DEPTH);
} stacks
SEC(".maps");


static __always_inline int record_cap(void *ctx, const struct cred *cred,
                                      struct user_namespace *targ_ns, int cap, int cap_opt) {
    u64 __pid_tgid = bpf_get_current_pid_tgid();
    gid_t tgid = __pid_tgid >> 32;
    pid_t pid = __pid_tgid;
    int audit;
    int insetid;

    if (LINUX_KERNEL_VERSION >= KERNEL_VERSION(5, 1, 0)) {
        // Field changed in v5.1.0
        audit = (cap_opt & 0b10) == 0;
        insetid = (cap_opt & 0b100) != 0;
    } else {
        audit = cap_opt;
        insetid = -1;
    }

    if (tool_config.tgid && tgid != tool_config.tgid) {
        return 0;
    }

    if (!tool_config.verbose && audit == 0) {
        return 0;
    }

    uid_t uid = bpf_get_current_uid_gid();

    struct event event = {.tgid = tgid, .pid = pid, .uid = uid, .cap = cap, .audit = audit,
            .insetid = insetid};
    if (tool_config.k_stacks) {
        event.kernel_stack_id = bpf_get_stackid(ctx, &stacks, 0);
    }
    if (tool_config.u_stacks) {
        event.user_stack_id = bpf_get_stackid(ctx, &stacks, BPF_F_USER_STACK);
    }

    if (tool_config.unique_type) {
        struct unique_stack_key key = {0};
        key.cap = cap;
        if (tool_config.unique_type == UnqCgroup) {
            key.cgroupid = bpf_get_current_cgroup_id();
        } else {
            key.tgid = tgid;
        }

        if (bpf_map_lookup_elem(&seen, &key) != NULL) {
            return 0;
        }
        u64 zero = 0;
        bpf_map_update_elem(&seen, &key, &zero, 0);
    }

    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

SEC("kprobe/cap_capable")

int BPF_KPROBE(kprobe__cap_capable, const struct cred *cred,
               struct user_namespace *targ_ns, int cap, int cap_opt) {
    return record_cap(ctx, cred, targ_ns, cap, cap_opt);

}

/*SEC("fentry/cap_capable")

int BPF_PROG(fentry__cap_capable, const struct cred *cred,
                        struct user_namespace *targ_ns, int cap, int cap_opt) {
    return record_cap(ctx, cred, targ_ns, cap, cap_opt);

}*/


char LICENSE[] SEC("license") = "GPL";
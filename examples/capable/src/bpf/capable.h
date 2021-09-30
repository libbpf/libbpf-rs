/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

#ifndef CAPABLE_CAPABLE_H
#define CAPABLE_CAPABLE_H

#define TASK_COMM_LEN 16
#define BPF_MAX_STACK_DEPTH 127

struct event {
	gid_t tgid;
	pid_t pid;
	uid_t uid;
	int cap;
	int audit;
	int insetid;
	u8 comm[TASK_COMM_LEN];
	int kernel_stack_id;
	int user_stack_id;
};

enum uniqueness {
	UNQ_OFF, UNQ_PID, UNQ_CGROUP
};

#endif //CAPABLE_CAPABLE_H

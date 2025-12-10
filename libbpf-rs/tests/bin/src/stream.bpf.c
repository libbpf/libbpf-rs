// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

/* Definition of can_loop taken from bpf_experimental.h. */
#ifdef __BPF_FEATURE_MAY_GOTO
#define can_loop                                                               \
    ({                                                                         \
        __label__ l_break, l_continue;                                         \
        bool ret = true;                                                       \
        asm volatile goto("may_goto %l[l_break]" :: ::l_break);                \
        goto l_continue;                                                       \
    l_break:                                                                   \
        ret = false;                                                           \
    l_continue:;                                                               \
        ret;                                                                   \
    })
#else
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define can_loop                                                               \
    ({                                                                         \
        __label__ l_break, l_continue;                                         \
        bool ret = true;                                                       \
        asm volatile goto("1:.byte 0xe5;		\
		      .byte 0;				\
		      .long ((%l[l_break] - 1b - 8) / 8) & 0xffff;	\
		      .short 0" :: ::l_break);                                 \
        goto l_continue;                                                       \
    l_break:                                                                   \
        ret = false;                                                           \
    l_continue:;                                                               \
        ret;                                                                   \
    })
#else
#define can_loop                                                               \
    ({                                                                         \
        __label__ l_break, l_continue;                                         \
        bool ret = true;                                                       \
        asm volatile goto("1:.byte 0xe5;		\
		      .byte 0;				\
		      .long (((%l[l_break] - 1b - 8) / 8) & 0xffff) << 16;	\
		      .short 0" :: ::l_break);                                 \
        goto l_continue;                                                       \
    l_break:                                                                   \
        ret = false;                                                           \
    l_continue:;                                                               \
        ret;                                                                   \
    })
#endif
#endif

volatile u64 i;

/*
 * Trigger a may_goto timeout to emit a streams error. As of 6.19 the only way
 * to trigger streams output is by causing an error condition in the program.
 * One of these is a loop timeout: The may_goto macro allows for loops that
 * cannot be verified by embedding a timer that is guaranteed to expire in the
 * condition, simplifying verification. When the timer expires, the kernel
 * writes an error message to the stderr stream of the BPF program. This is the
 * case below.
 */
SEC("syscall")
int trigger_streams(void *ctx)
{
    while (i == 0 && can_loop)
        ;
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

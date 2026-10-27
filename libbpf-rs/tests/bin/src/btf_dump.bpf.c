// SPDX-License-Identifier: GPL-2.0

/* A simple program providing fixed BTF for `BtfDump` tests. */

typedef unsigned int u32;

struct point {
    u32 x;
    u32 y;
};

typedef struct point point_t;

int sum(point_t *p)
{
    return p->x + p->y;
}

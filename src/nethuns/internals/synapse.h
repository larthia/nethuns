#pragma once

#include <stddef.h>
#include <stdint.h>

#include "compiler.h"

#define MAX(a,b) \
    ({ __typeof__ (a) _a = (a); \
      __typeof__ (b) _b = (b); \
      _a > _b ? _a : _b; })

#define MIN(a,b) \
    ({ __typeof__ (a) _a = (a); \
      __typeof__ (b) _b = (b); \
      _a < _b ? _a : _b; })


struct nethuns_synapse
{
    unsigned int number;
    uint64_t id[256];
};


static inline uint64_t
nethuns_synpse_min(struct nethuns_synapse *sync)
{
    uint64_t cur = UINT64_MAX;
    unsigned int i;
    for(i = 0; i < sync->number; i++)
        cur = MIN(cur, __atomic_load_n(&sync->id[i], __ATOMIC_ACQUIRE));

    return cur;
}


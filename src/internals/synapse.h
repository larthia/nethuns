#pragma once

#include <stddef.h>

#ifndef likely
#define likely(x) __builtin_expect((x),1)
#endif

#ifndef unlikely
#define unlikely(x)	__builtin_expect((x),0)
#endif

#ifndef __cachedline_aligned
#define __cacheline_aligned		__attribute__((aligned(64)))
#endif


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

    struct _id
    {
        uint64_t value;
    } __cachedline_aligned;

    struct _id id[256];
};



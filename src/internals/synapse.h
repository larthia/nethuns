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


struct nethuns_synapse
{
    size_t nconsumer;

    struct _id
    {
        size_t value;
    } __cachedline_aligned;

    struct _id id[1024];
};

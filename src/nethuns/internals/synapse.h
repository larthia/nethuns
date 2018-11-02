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

    struct _id
    {
        uint64_t value;
    } __cachedline_aligned;

    struct _id id[256];
};



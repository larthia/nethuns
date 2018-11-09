#pragma once

#define MAX(a,b) \
        ({ __typeof__ (a) _a = (a); \
               __typeof__ (b) _b = (b); \
                     _a > _b ? _a : _b; })

#define MIN(a,b) \
        ({ __typeof__ (a) _a = (a); \
               __typeof__ (b) _b = (b); \
                     _a < _b ? _a : _b; })

#ifndef likely
#define likely(x) __builtin_expect((x),1)
#endif

#ifndef unlikely
#define unlikely(x) __builtin_expect((x),0)
#endif

#ifndef __cachedline_aligned
#define __cacheline_aligned     __attribute__((aligned(64)))
#endif

#ifndef __maybe_unused
# define __maybe_unused     __attribute__((unused))
#endif


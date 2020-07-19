#pragma once

#ifndef likely
#define likely(x) __builtin_expect((x),1)
#endif

#ifndef unlikely
#define unlikely(x) __builtin_expect((x),0)
#endif

#ifndef __cacheline_aligned
#define __cacheline_aligned     __attribute__((aligned(64)))
#endif

#ifndef  __maybe_unused
# define __maybe_unused     __attribute__((unused))
#endif


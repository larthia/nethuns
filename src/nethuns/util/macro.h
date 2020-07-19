#pragma once

#ifndef MAX
#define MAX(a,b) \
        ({ __typeof__ (a) _a = (a); \
               __typeof__ (b) _b = (b); \
                     _a > _b ? _a : _b; })
#endif

#ifndef MIN
#define MIN(a,b) \
        ({ __typeof__ (a) _a = (a); \
               __typeof__ (b) _b = (b); \
                     _a < _b ? _a : _b; })
#endif
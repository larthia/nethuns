// Copyright 2021 Larthia, University of Pisa. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

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
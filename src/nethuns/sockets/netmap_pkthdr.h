// Copyright 2021 Larthia, University of Pisa. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#pragma once

#include <sys/time.h>
#include <stdint.h>

struct netmap_pkthdr {
        struct timeval ts;
	uint32_t len;
	uint32_t caplen;
        uint32_t buf_idx;
};

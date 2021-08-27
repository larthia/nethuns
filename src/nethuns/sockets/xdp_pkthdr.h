// Copyright 2021 Larthia, University of Pisa. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#pragma once

#include <stdint.h>

struct xdp_pkthdr {
	uint32_t sec;
	uint32_t nsec;
	uint32_t len;
	uint32_t snaplen;
};

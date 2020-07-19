#pragma once

#include <stdint.h>

struct xdp_pkthdr {
	uint32_t sec;
	uint32_t nsec;
	uint32_t len;
	uint32_t snaplen;
};

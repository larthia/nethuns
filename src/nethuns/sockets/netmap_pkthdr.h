#pragma once

#include <sys/time.h>
#include <stdint.h>

struct netmap_pkthdr {
        struct timeval ts;
	uint32_t len;
	uint32_t caplen;
};

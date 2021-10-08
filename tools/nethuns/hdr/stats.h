#pragma once

#include <stdint.h>

struct stats {
    uint64_t pkt_count;
    uint64_t byte_count;
} __attribute((aligned(64)));
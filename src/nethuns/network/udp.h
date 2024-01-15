#pragma once

#include <nethuns/network/endian.h>

#include <string.h>
#include <stdint.h>

struct udp_hdr
{
    uint16_t source;
    uint16_t dest;
    uint16_t len;
    uint16_t check;
} __attribute__((packed, aligned(2)));

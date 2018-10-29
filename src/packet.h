#pragma once

#include "internals/packet.h"
#include <stdint.h>


struct nethuns_packet
{
    uint8_t const     *payload;
    nethuns_pkthdr_t   pkthdr;
    nethuns_socket_t   socket;
    uint64_t           block;
};


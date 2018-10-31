#pragma once

#include "internals/packet.h"
#include <stdint.h>
#include <stdbool.h>


struct nethuns_packet
{
    uint8_t const     *payload;
    nethuns_pkthdr_t  *pkthdr;
    nethuns_socket_t  *socket;
    uint64_t           id;
};


struct nethuns_socket_options
{
    unsigned int    numblocks;
    unsigned int    numpackets;
    unsigned int    packetsize;
    unsigned int    timeout;
    bool            rxhash;
};


struct nethuns_stats
{
    uint64_t     packets;
    uint64_t     drops;
    uint64_t     freeze;
};

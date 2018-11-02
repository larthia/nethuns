#pragma once

#include "internals/synapse.h"
#include "internals/types.h"
#include <stdint.h>
#include <stdbool.h>


#define NETHUNS_ERRBUF_SIZE     512


struct nethuns_socket_options
{
    unsigned int    numblocks;
    unsigned int    numpackets;
    unsigned int    packetsize;
    unsigned int    timeout;
    bool            rxhash;
    bool            tx_qdisc_bypass;
};


struct nethuns_socket_base
{
    struct nethuns_synapse        sync;
    struct nethuns_socket_options opt;
    char   errbuf[NETHUNS_ERRBUF_SIZE];
};


struct nethuns_stats
{
    uint64_t     packets;
    uint64_t     drops;
    uint64_t     freeze;
};


struct nethuns_packet
{
    uint8_t const     *payload;
    nethuns_pkthdr_t  *pkthdr;
    nethuns_socket_t  *socket;
    uint64_t           id;
};



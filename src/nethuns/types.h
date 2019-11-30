#pragma once

#include "priv/ring.h"
#include "priv/types.h"
#include <stdint.h>
#include <stdbool.h>


#define NETHUNS_ERRBUF_SIZE     512
#define NETHUNS_ANY_QUEUE       (-1)


enum nethuns_capture_dir
{
    nethuns_in
,   nethuns_out
,   nethuns_in_out
};


struct nethuns_socket_options
{
    unsigned int                numblocks;
    unsigned int                numpackets;
    unsigned int                packetsize;
    unsigned int                timeout_ms;
    enum nethuns_capture_dir    dir;
    bool                        promisc;
    bool                        rxhash;
    bool                        tx_qdisc_bypass;
};


struct nethuns_socket_data
{
    char   errbuf[NETHUNS_ERRBUF_SIZE];

    struct nethuns_socket_options opt;
    struct nethuns_ring           ring;
    char                         *devname;
    int                           queue;
    bool                          clear_promisc;
};


typedef struct nethuns_socket_data  nethuns_socket_data_t;


struct nethuns_stats
{
    uint64_t     packets;
    uint64_t     drops;
    uint64_t     ifdrops;
    uint64_t     freeze;
};


struct nethuns_packet
{
    uint8_t const                 *payload;
    const nethuns_pkthdr_t        *pkthdr;
    nethuns_socket_data_t         *sock;
    uint64_t                       id;
};



#pragma once

#include <sys/time.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

#include "sockets/types.h"


enum nethuns_capture_dir
{
    nethuns_in
,   nethuns_out
,   nethuns_in_out
};


enum nethuns_capture_mode
{
    nethuns_cap_default
  , nethuns_cap_skb_mode
  , nethuns_cap_drv_mode
  , nethuns_cap_zero_copy
};


enum nethuns_socket_mode
{
    nethuns_socket_rx_tx
 ,  nethuns_socket_rx_only
 ,  nethuns_socket_tx_only
};


struct nethuns_socket_options
{
    unsigned int                numblocks;
    unsigned int                numpackets;
    unsigned int                packetsize;
    unsigned int                timeout_ms;
    enum nethuns_capture_dir    dir;
    enum nethuns_capture_mode 	capture;
    enum nethuns_socket_mode 	mode;
    bool                        promisc;
    bool                        rxhash;
    bool                        tx_qdisc_bypass;
    const char                  *xdp_prog;
};


struct nethuns_stat
{
    uint64_t     rx_packets;
    uint64_t     tx_packets;
    uint64_t     rx_dropped;
    uint64_t     rx_if_dropped;
    uint64_t     rx_invalid;        // xdp only
    uint64_t     tx_invalid;        // xdp only
    uint64_t     freeze;
};


struct nethuns_socket_base;
struct nethuns_packet
{
    uint8_t const                 *payload;
    const nethuns_pkthdr_t        *pkthdr;
    struct nethuns_socket_base    *sock;
    uint64_t                       id;
};


struct nethuns_timeval
{
    uint32_t    tv_sec;
    uint32_t    tv_usec;
};

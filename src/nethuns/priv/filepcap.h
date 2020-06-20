#pragma once

#ifdef NETHUNS_USE_TPACKET_V3
#include <linux/if_packet.h>
#endif

#ifndef NETHUNS_USE_NATIVE_PCAPFILE_READER
#include <pcap/pcap.h>
#endif

#include <sys/time.h>
#include <stdio.h>

#include "../types.h"

struct nethuns_pcap_file_header
{
    uint32_t        magic;
    unsigned short  version_major;
    unsigned short  version_minor;
    int32_t         thiszone;       /* gmt to local correction */
    uint32_t        sigfigs;        /* accuracy of timestamps */
    uint32_t        snaplen;        /* max length saved portion of each pkt */
    uint32_t        linktype;       /* data link type (LINKTYPE_*) */
};


struct nethuns_timeval
{
    uint32_t    tv_sec;
    uint32_t    tv_usec;
};


struct nethuns_pcap_pkthdr
{
    struct nethuns_timeval ts;      /* time stamp */
    uint32_t caplen;                /* length of portion present */
    uint32_t len;                   /* length this packet (off wire) */
};


typedef struct nethuns_pcap_socket nethuns_pcap_t;

struct nethuns_pcap_socket
{
    struct nethuns_socket_data      base;
#ifdef NETHUNS_USE_NATIVE_PCAPFILE_READER
    FILE *              r;
#else
    pcap_t *            r;
#endif
    FILE *              w;
    uint32_t            snaplen;
};


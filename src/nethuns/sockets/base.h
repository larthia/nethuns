#pragma once

#include "../define.h"
#include "../filter.h"
#include "../types.h"

struct nethuns_ring_slot;

struct nethuns_ring
{
    size_t size;
    size_t pktsize;

    uint64_t head;
    uint64_t tail;

    struct nethuns_ring_slot *ring;
};

struct nethuns_socket_base
{
    char   errbuf[NETHUNS_ERRBUF_SIZE];

    struct nethuns_socket_options opt;
    struct nethuns_ring           ring;
    char                         *devname;
    int                           queue;
    int 		                  ifindex;

    nethuns_filter_t              filter;
    void *                        filter_ctx;
};


typedef struct nethuns_socket_base  nethuns_socket_base_t;

struct nethuns_pcap_pkthdr
{
    struct nethuns_timeval ts;      /* time stamp */
    uint32_t caplen;                /* length of portion present */
    uint32_t len;                   /* length this packet (off wire) */
};


struct nethuns_pcap_patched_pkthdr {
    struct nethuns_timeval ts;	    /* time stamp */
    uint32_t caplen;		        /* length of portion present */
    uint32_t len;		            /* length of this packet (off wire) */
    int		 index;
    unsigned short protocol;
    unsigned char pkt_type;
};


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


struct nethuns_socket_pcapfile
{
    struct nethuns_socket_base  base;
#ifdef NETHUNS_USE_BUILTIN_PCAP_READER
    FILE *              r;
#else
    pcap_t *            r;
#endif
    uint32_t            snaplen;
    uint32_t            magic;
};

typedef struct nethuns_socket_pcapfile nethuns_pcap_t;

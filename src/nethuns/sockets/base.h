#pragma once

#include "../define.h"
#include "../types.h"

struct nethuns_ring_slot;

typedef int (*nethuns_filter_t)(void *ctx, const nethuns_pkthdr_t *pkthdr, const uint8_t *pkt);

#ifndef TEMPLATE_
#define TEMPLATE_(x,y) x ## y
#define TEMPLATE(x,y) TEMPLATE_(x,y) 
#endif

struct nethuns_ring
{
    size_t size;
    size_t pktsize;

    uint64_t head;
    uint64_t tail;

    size_t mask;
    size_t shift;

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

#define nethuns_socket(_sock)       ((struct nethuns_socket_base *)(_sock))
#define nethuns_const_socket(_sock) ((struct nethuns_socket_base const *)(_sock))


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
    void *              r;              // either FILE * or pcap_t *, depending on the value of NETHUNS_USE_BULTIN_PCAP_READER
    uint32_t            snaplen;
    uint32_t            magic;
};

typedef struct nethuns_socket_pcapfile nethuns_pcap_t;

static inline void
nethuns_set_filter(nethuns_socket_t * s, nethuns_filter_t filter, void *ctx)
{
    nethuns_socket(s)->filter = filter;
    nethuns_socket(s)->filter_ctx = ctx;
}

static inline void
nethuns_clear_filter(nethuns_socket_t * s)
{
    nethuns_socket(s)->filter = NULL;
    nethuns_socket(s)->filter_ctx = NULL;
}

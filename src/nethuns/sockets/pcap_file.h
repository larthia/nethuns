#pragma once

#ifdef NETHUNS_USE_TPACKET_V3
#include <linux/if_packet.h>
#endif

#ifndef NETHUNS_USE_BUILTIN_PCAP_READER
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

typedef struct nethuns_pcap_socket nethuns_pcap_t;

struct nethuns_pcap_socket
{
    struct nethuns_socket_base      base;
#ifdef NETHUNS_USE_BUILTIN_PCAP_READER
    FILE *              r;
#else
    pcap_t *            r;
#endif
    uint32_t            snaplen;
    uint32_t            magic;
};

#ifdef __cplusplus
extern "C" {
#endif

#ifdef NETHUNS_USE_BUILTIN_PCAP_READER
static inline
int nethuns_pcap_write(nethuns_pcap_t *s, struct nethuns_pcap_pkthdr const *header, uint8_t const *packet, unsigned int len)
{
    fwrite(header, sizeof(struct nethuns_pcap_pkthdr), 1, s->r);
    if (fwrite(packet, 1, len, s->r) != len) {
        return -1;
    }
    fflush(s->r);
    return len;
}
#else
static inline
int nethuns_pcap_write(nethuns_pcap_t *s, struct nethuns_pcap_pkthdr const *header, uint8_t const *packet, unsigned int len)
{
    (void)s;
    (void)header;
    (void)packet;
    (void)len;
    return -1;
}
#endif

#ifdef __cplusplus
}
#endif

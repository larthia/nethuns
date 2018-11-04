#pragma once

#ifdef NETHUNS_USE_TPACKET_V3
#include <linux/if_packet.h>
#endif
#ifdef NETHUNS_USE_DEVPCAP
#include <pcap/pcap.h>
#endif

#include <stdlib.h>
#include <stdint.h>

struct nethuns_ring_slot
{
#if defined (NETHUNS_USE_TPACKET_V3)
    struct tpacket3_hdr     pkthdr;
#elif defined (NETHUNS_USE_DEVPCAP)
    struct pcap_pkthdr      pkthdr;
#endif
    uint64_t                id;
    int                     inuse;
    unsigned char           packet[];
};


struct nethuns_ring
{
    size_t size;
    size_t pktsize;

    uint64_t last_id;

    uint64_t head;
    uint64_t tail;

    struct nethuns_ring_slot ring[];
};


static inline
struct nethuns_ring *
nethuns_make_ring(size_t nslots, size_t pktsize)
{
    struct nethuns_ring * r = (struct nethuns_ring *)calloc(1, sizeof(struct nethuns_ring) +
                                                               nslots * (sizeof(struct nethuns_ring_slot) + pktsize));

    r->size    = nslots;
    r->pktsize = pktsize;
    r->last_id = 0;
    r->head    = 0;
    r->tail    = 0;

    return r;
}


static inline
struct nethuns_ring_slot *
nethuns_ring_get_slot(struct nethuns_ring *ring, size_t n)
{
    return (struct nethuns_ring_slot *)
            ((char *)ring->ring +
                (n % ring->size) * (sizeof(struct nethuns_ring_slot) + ring->pktsize));
}


static inline uint64_t
nethuns_ring_last_free_id(struct nethuns_ring *ring)
{
    while (ring->tail != ring->head && !nethuns_ring_get_slot(ring, ring->tail)->inuse)
    {
        ring->last_id = nethuns_ring_get_slot(ring, ring->tail)->id;
        ring->tail++;
    }

    return ring->last_id;
}


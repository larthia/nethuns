#pragma once

#include "../types.h"

#ifdef NETHUNS_USE_DEVPCAP
#include <pcap/pcap.h>
#endif

#include <stdlib.h>

struct nethuns_ring_slot
{
#if defined (NETHUNS_USE_TPACKET_V3)
    struct tpacket3_hdr     pkthdr;
#elif defined (NETHUNS_USE_DEVPCAP)
    struct pcap_pkthdr      pkthdr;
#endif
    int                     inuse;
    unsigned char           packet[];
};


struct nethuns_ring
{
    size_t size;
    size_t psize;
    struct nethuns_ring_slot ring[];
};


static inline
struct nethuns_ring *
nethuns_make_ring(size_t nslots, size_t psize)
{
    struct nethuns_ring * r = (struct nethuns_ring *)calloc(1, sizeof(struct nethuns_ring) +
                                                               nslots * (sizeof(struct nethuns_ring_slot) + psize));

    r->size  = nslots;
    r->psize = psize;
    return r;
}


static inline
struct nethuns_ring_slot *
nethuns_ring_slot_mod(struct nethuns_ring *ring, size_t n)
{
    struct nethuns_ring_slot * slot =
            (struct nethuns_ring_slot *)
            ((char *)ring->ring +
                (n % ring->size) * (sizeof(struct nethuns_ring_slot) + ring->psize));

    return slot;
}



#pragma once

#include "../types.h"


struct nethuns_ring_slot
{
#ifdef NETHUNS_USE_TPACKET_V3
    struct tpacket3_hdr     pkthdr;
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
    struct nethuns_ring * r = calloc(1, sizeof(struct nethuns_ring) +
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



#pragma once

#ifdef NETHUNS_USE_TPACKET_V3
#include <linux/if_packet.h>
#endif

#ifdef NETHUNS_USE_NETMAP
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>
#endif
#ifdef NETHUNS_USE_DEVPCAP
#include <pcap/pcap.h>
#endif

#ifdef NETHUNS_USE_XDP
#include "xdp_pkthdr.h"
#endif

#include <stdlib.h>
#include <stdint.h>

#include "../util/macro.h"
#include "../util/compiler.h"

struct nethuns_ring_slot
{
#if defined (NETHUNS_USE_TPACKET_V3)
    struct tpacket3_hdr     pkthdr;
#elif defined (NETHUNS_USE_NETMAP)
    struct nm_pkthdr        pkthdr;
#elif defined (NETHUNS_USE_DEVPCAP)
    struct pcap_pkthdr      pkthdr;
#elif defined (NETHUNS_USE_XDP)
    struct xdp_pkthdr       pkthdr;
    uint64_t                orig;
    int32_t                 idx_fq;
#endif
    uint64_t                id;
    int                     inuse;
    unsigned char           pad[2];

#if defined (NETHUNS_USE_XDP)
    unsigned char           *packet;
#else
    unsigned char           packet[];
#endif
};


struct nethuns_ring
{
    size_t size;
    size_t pktsize;

    uint64_t head;
    uint64_t tail;

    struct nethuns_ring_slot *ring;
};


static inline
int
nethuns_make_ring(size_t nslots, size_t pktsize, struct nethuns_ring *r)
{
    r->size    = nslots;
    r->pktsize = pktsize;
    r->head    = 0;
    r->tail    = 0;
    r->ring    = (struct nethuns_ring_slot *)calloc(1, nslots * (sizeof(struct nethuns_ring_slot) + pktsize));

    return r->ring ? 0 : -1;
}


static inline
struct nethuns_ring_slot *
nethuns_ring_get_slot(struct nethuns_ring *ring, size_t n)
{
    return (struct nethuns_ring_slot *)
            ((char *)ring->ring + (n % ring->size) * (sizeof(struct nethuns_ring_slot) + ring->pktsize));
}


static inline
size_t
nethuns_ring_num_free_slots(struct nethuns_ring *ring, size_t n)
{
    size_t last = n + MIN(ring->size - 1, (size_t)32);
    size_t total = 0;
    for (size_t x = n; x < last; x++)
    {
        struct nethuns_ring_slot *s = nethuns_ring_get_slot(ring, x);
        if (likely(!__atomic_load_n(&s->inuse, __ATOMIC_ACQUIRE))) {
            total++;
        }
        else {
            break;
        }
    }

    return total;
}

static inline
struct nethuns_ring_slot *
nethuns_ring_next_slot(struct nethuns_ring *ring)
{
    return nethuns_ring_get_slot(ring,ring->head++);
}


typedef int(*nethuns_free_slot_t)(struct nethuns_ring_slot *slot, uint64_t id, void *user);


static inline int
nethuns_ring_free_slots(struct nethuns_ring *ring, nethuns_free_slot_t cb, void *user)
{
    int n = 0;

    struct nethuns_ring_slot *slot = nethuns_ring_get_slot(ring, ring->tail);

    while (ring->tail != ring->head && !__atomic_load_n(&slot->inuse, __ATOMIC_ACQUIRE))
    {
        cb(slot, nethuns_ring_get_slot(ring, ring->tail)->id, user);
        slot = nethuns_ring_get_slot(ring, ++ring->tail);
    }

    return n;
}

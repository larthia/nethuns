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

#include <stdlib.h>
#include <stdint.h>

struct nethuns_ring_slot
{
#if defined (NETHUNS_USE_TPACKET_V3)
    struct tpacket3_hdr     pkthdr;
#elif defined (NETHUNS_USE_NETMAP)
    struct nm_pkthdr        pkthdr;
#elif defined (NETHUNS_USE_DEVPCAP)
    struct pcap_pkthdr      pkthdr;
#endif
    uint64_t                id;
    int                     inuse;
    unsigned char           pad[2];
    unsigned char           packet[];
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
nethuns_get_ring_slot(struct nethuns_ring *ring, size_t n)
{
    return (struct nethuns_ring_slot *)
            ((char *)ring->ring + (n % ring->size) * (sizeof(struct nethuns_ring_slot) + ring->pktsize));
}


static inline
struct nethuns_ring_slot *
nethuns_ring_next(struct nethuns_ring *ring)
{
    return nethuns_get_ring_slot(ring,ring->head++);
}


typedef int(*nethuns_free_id_t)(uint64_t id, void *user);


static inline int
nethuns_ring_free_id(struct nethuns_ring *ring, nethuns_free_id_t cb, void *user)
{
    int n = 0;

    while (ring->tail != ring->head && !__atomic_load_n(&nethuns_get_ring_slot(ring, ring->tail)->inuse, __ATOMIC_ACQUIRE))
    {
        cb(nethuns_get_ring_slot(ring, ring->tail)->id, user);
        ring->tail++;
    }

    return n;
}





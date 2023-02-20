// Copyright 2021 Larthia, University of Pisa. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#pragma once

#include "base.h"

#include "../define.h"

#if !defined NETHUNS_SOCKET
#error NETHUNS_SOCKET is not defined.
#endif

#if NETHUNS_SOCKET == NETHUNS_SOCKET_LIBPCAP
#include <pcap/pcap.h>
#endif

#if NETHUNS_SOCKET == NETHUNS_SOCKET_TPACKET3
#include <linux/if_packet.h>
#endif

#if NETHUNS_SOCKET == NETHUNS_SOCKET_NETMAP
#include "netmap_pkthdr.h"
#endif


#if NETHUNS_SOCKET == NETHUNS_SOCKET_XDP
#include "xdp_pkthdr.h"
#endif

#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <limits.h>

#include "../misc/macro.h"
#include "../misc/compiler.h"
#include "../types.h"

struct nethuns_ring_slot
{
#if NETHUNS_SOCKET == NETHUNS_SOCKET_TPACKET3
    struct tpacket3_hdr     pkthdr;
#elif NETHUNS_SOCKET == NETHUNS_SOCKET_NETMAP
    struct netmap_pkthdr        pkthdr;
#elif NETHUNS_SOCKET == NETHUNS_SOCKET_LIBPCAP
    struct pcap_pkthdr      pkthdr;
#elif NETHUNS_SOCKET == NETHUNS_SOCKET_XDP
    struct xdp_pkthdr       pkthdr;
#else
#error "NETHUNS_SOCKET not defined"
#endif
    uint64_t                id;
    int                     inuse;
    int32_t                 len;

#if NETHUNS_SOCKET == NETHUNS_SOCKET_XDP
    unsigned char           *packet;
    uint64_t 		        addr;
#else
    unsigned char           packet[];
#endif
};


static inline
size_t
nethuns_lpow2(size_t n)
{
    if (n && !(n & (n - 1)))
        return n;
    return 1UL << (sizeof(size_t) * CHAR_BIT - __builtin_clzl(n));
}

static inline
int
nethuns_make_ring(size_t nslots, size_t pktsize, struct nethuns_ring *r)
{
    size_t ns = nethuns_lpow2(nslots);
    size_t ss = nethuns_lpow2(sizeof(struct nethuns_ring_slot) + pktsize);

    r->size    = nslots;
    r->pktsize = pktsize;
    r->head    = 0;
    r->tail    = 0;
    r->ring    = (struct nethuns_ring_slot *)calloc(1, ns * ss);
    r->mask    = ns - 1;
    r->shift   = __builtin_ctzl(ss);

    return r->ring ? 0 : -1;
}

static inline
void
nethuns_delete_ring(struct nethuns_ring *r)
{
    free(r->ring);
    memset(r, 0, sizeof(*r));
}


static inline
struct nethuns_ring_slot *
nethuns_ring_get_slot(struct nethuns_ring *ring, size_t n)
{
    return (struct nethuns_ring_slot *)
            ((char *)ring->ring + ((n & ring->mask) << ring->shift));
}

static inline
uint64_t
nethuns_slot_get_idx(struct nethuns_ring *ring, struct nethuns_ring_slot *s)
{
	return (uint64_t)((char *)ring->ring - (char *)s) >> ring->shift;
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

#define nethuns_rx_release(_sock, _pktid) do \
{ \
    __atomic_store_n(&nethuns_ring_get_slot(&nethuns_socket(_sock)->rx_ring, (_pktid)-1)->inuse, 0, __ATOMIC_RELEASE); \
} while (0)

#define nethuns_tx_release(_sock, _pktid) do \
{ \
    __atomic_store_n(&(nethuns_ring_get_slot(&nethuns_socket(_sock)->tx_ring, (_pktid)-1)->inuse), 0, __ATOMIC_RELEASE); \
} while (0)


static inline int
nethuns_send_slot(nethuns_socket_t *sock, uint64_t pktid, size_t len)
{
    struct nethuns_ring_slot * slot = nethuns_ring_get_slot(&nethuns_socket(sock)->tx_ring, pktid);
    if (__atomic_load_n(&slot->inuse, __ATOMIC_ACQUIRE))
        return 0;
    slot->len = len;
    __atomic_store_n(&slot->inuse, 1, __ATOMIC_RELEASE);
    return 1;
}

static inline
size_t
nethuns_rxring_get_size(nethuns_socket_t *s)
{
    return nethuns_socket(s)->rx_ring.mask + 1;
}

static inline
size_t
nethuns_txring_get_size(nethuns_socket_t *s)
{
    return nethuns_socket(s)->tx_ring.mask + 1;
}

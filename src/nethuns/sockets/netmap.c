/**
 * Copyright 2021 Larthia, University of Pisa. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#ifdef NETHUNS_SOCKET
#undef NETHUNS_SOCKET
#endif

#define NETHUNS_SOCKET NETHUNS_SOCKET_NETMAP
#include "ring.h"
#include "netmap.h"

#define SOCKET_TYPE netmap
#include "file.inc"

#include "../misc/compiler.h"
#include "../api.h"

#include <sys/ioctl.h>
#include <sys/poll.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


struct nethuns_socket_netmap *
nethuns_open_netmap(struct nethuns_socket_options *opt, char *errbuf)
{
    struct nethuns_socket_netmap *s;

    s = calloc(1, sizeof(struct nethuns_socket_netmap));
    if (!s)
    {
        nethuns_perror(errbuf, "open: could not allocate socket");
        goto err_out;
    }

    s->rx = false;
    s->tx = false;

    if (opt->mode == nethuns_socket_rx_tx || opt->mode == nethuns_socket_rx_only)
    {
        s->rx = true;
    }

    if (opt->mode == nethuns_socket_rx_tx || opt->mode == nethuns_socket_tx_only)
    {
        s->tx = true;
    }

	if (!s->rx && !s->tx)
    {
		nethuns_perror(errbuf, "open: please select at least one between rx and tx");
		goto err_free;
	}


    if (s->rx)
    {
        if (nethuns_make_ring(opt->numblocks * opt->numpackets, opt->packetsize, &s->base.rx_ring) < 0)
        {
            nethuns_perror(errbuf, "open: failed to allocate ring");
            goto err_free;
        }
    }

    if (s->tx)
    {
        if (nethuns_make_ring(opt->numblocks * opt->numpackets, opt->packetsize, &s->base.tx_ring) < 0)
        {
            nethuns_perror(errbuf, "open: failed to allocate ring");
            goto err_del_ring;
        }
    }

    /* set a single consumer by default */

    s->base.opt = *opt;
    return s;

    err_del_ring:
    if (s->rx)
    {
	    nethuns_delete_ring(&s->base.rx_ring);
    }
    err_free:
    free(s);
    err_out:
    return NULL;
}


int nethuns_close_netmap(struct nethuns_socket_netmap *s)
{
    struct netmap_if *nifp;
    uint32_t idx, *next;
    struct nethuns_socket_base *b = nethuns_socket(s);

    if (s)
    {
        if (b->opt.promisc)
        {
            __nethuns_clear_if_promisc(s, b->devname);
        }
        nifp = s->p->nifp;
        if (s->tx)
        {
            size_t i;
            for (i = 0; i < b->tx_ring.size; i++)
            {
                struct nethuns_ring_slot *slot = nethuns_ring_get_slot(&b->tx_ring, i);
                {
                    idx = slot->pkthdr.buf_idx;
                    next = (uint32_t *)NETMAP_BUF(s->some_ring, idx);

                    *next = nifp->ni_bufs_head;
                    nifp->ni_bufs_head = idx;
                }
            }
        }

        for ( ; s->free_head != s->free_tail; s->free_head++)
        {
            idx = s->free_ring[s->free_head & s->free_mask];
            next = (uint32_t *)NETMAP_BUF(s->some_ring, idx);

            *next = nifp->ni_bufs_head;
            nifp->ni_bufs_head = idx;
        }

        nmport_close(s->p);

        __nethuns_free_base(s);
        free(s);
    }
    return 0;
}


int nethuns_bind_netmap(struct nethuns_socket_netmap *s, const char *dev, int queue)
{
    static const int NMDEVSZ = 128;
    char nm_dev[NMDEVSZ];
    const char *flags = "", *prefix = "netmap:";
    struct nethuns_socket_base *b = nethuns_socket(s);
    uint32_t extra_bufs;
    uint32_t scan;

    if (!s->tx)
    {
        flags = "/R";
    }
    else if (!s->rx)
    {
        flags = "/T";
    }

    if (!strncmp(dev, "vale", 4))
    {
        prefix = "";
    }

    if (queue == NETHUNS_ANY_QUEUE)
    {
        snprintf(nm_dev, NMDEVSZ, "%s%s%s", prefix, dev, flags);
    }
    else
    {
        snprintf(nm_dev, NMDEVSZ, "%s%s-%d%s", prefix, dev, queue, flags);
    }

    s->p = nmport_prepare(nm_dev);
    if (!s->p)
    {
        nethuns_perror(s->base.errbuf, "bind: could not open dev: %s", nethuns_dev_queue_name(dev, queue));
        return -1;
    }

    nethuns_socket(s)->queue   = queue;
    nethuns_socket(s)->ifindex = (int)if_nametoindex(dev);

    extra_bufs = !!s->tx * s->base.rx_ring.size + !!s->rx * s->base.tx_ring.size;
    s->p->reg.nr_extra_bufs = extra_bufs;

    if (nmport_open_desc(s->p) < 0) {
        nethuns_perror(s->base.errbuf, "open: could open dev %s (%s)", nethuns_dev_queue_name(dev, queue),
			strerror(errno));
        return -1;
    }

    if (s->p->reg.nr_extra_bufs != extra_bufs) {
        nethuns_perror(s->base.errbuf, "dev %s: cannot obtain %u extra bufs (got %u)",
			nethuns_dev_queue_name(dev, queue),
                extra_bufs, s->p->reg.nr_extra_bufs);
        return -1;
    }

    s->some_ring = NETMAP_RXRING(s->p->nifp, s->rx ? s->p->first_rx_ring : s->p->first_tx_ring);

    extra_bufs = nethuns_lpow2(s->p->reg.nr_extra_bufs);
    s->free_ring = calloc(1, sizeof(uint32_t) * extra_bufs);
    if (!s->free_ring)
    {
        nethuns_perror(s->base.errbuf, "dev %s: out-of-memory while allocating free bufs list",
			nethuns_dev_queue_name(dev, queue));
        return -1;
    }
    s->free_mask = extra_bufs - 1;

    scan = s->p->nifp->ni_bufs_head;
    if (s->tx) {
        size_t i;

        for (i = 0; i < b->tx_ring.size; i++, scan = *(uint32_t *)NETMAP_BUF(s->some_ring, scan))
        {
            struct nethuns_ring_slot *slot = nethuns_ring_get_slot(&b->tx_ring, i);
            slot->pkthdr.buf_idx = scan;
        }
    }

    if (s->rx) {
        for ( ; scan; scan = *(uint32_t *)NETMAP_BUF(s->some_ring, scan))
        {
            s->free_ring[s->free_tail & s->free_mask] = scan;
            s->free_tail++;
        }
    }
    s->p->nifp->ni_bufs_head = 0;

    nethuns_socket(s)->devname = strdup(dev);

    if (b->opt.promisc)
    {
        if (__nethuns_set_if_promisc(s, nethuns_socket(s)->devname) < 0) {
            nethuns_perror(s->base.errbuf, "bind: could set promisc: %s", nethuns_dev_queue_name(dev, queue));
            return -1;
	    }
    }

    sleep(2);
    return 0;
}

static struct netmap_ring *
non_empty_rxring(struct nmport_d *d)
{
    int ri = d->cur_rx_ring;

    do {
        /* compute current ring to use */
        struct netmap_ring *ring = NETMAP_RXRING(d->nifp, ri);
        if (ring->cur != ring->tail) {
            d->cur_rx_ring = ri;
            return ring;
        }
        ri++;
        if (ri > d->last_rx_ring)
            ri = d->first_rx_ring;
    } while (ri != d->cur_rx_ring);
    return NULL; /* nothing found */
}

static int
nethuns_blocks_free(struct nethuns_ring_slot *slot,  __maybe_unused uint64_t blockid, __maybe_unused void *user)
{
    struct nethuns_socket_netmap *s = (struct nethuns_socket_netmap *)user;

    s->free_ring[s->free_tail & s->free_mask] = slot->pkthdr.buf_idx;
    s->free_tail++;
    return 0;
}

uint64_t
nethuns_recv_netmap(struct nethuns_socket_netmap *s, nethuns_pkthdr_t const **pkthdr, uint8_t const **payload)
{
    unsigned int caplen = s->base.opt.packetsize;
    unsigned int bytes;
    const uint8_t *pkt;
    struct netmap_ring *ring;
    u_int i, idx;

    struct nethuns_ring_slot * slot = nethuns_ring_get_slot(&s->base.rx_ring, s->base.rx_ring.head);
    if (__atomic_load_n(&slot->inuse, __ATOMIC_ACQUIRE))
    {
        return 0;
    }

    if (unlikely(s->free_head == s->free_tail))
    {
        nethuns_ring_free_slots(&s->base.rx_ring, nethuns_blocks_free, s);
        if (unlikely(s->free_head == s->free_tail))
        {
            return 0;
        }
    }

    ring = non_empty_rxring(s->p);
    if (unlikely(!ring))
    {
        ioctl(s->p->fd, NIOCRXSYNC);
        ring = non_empty_rxring(s->p);
        if (unlikely(!ring))
            return 0;

        //
        // struct pollfd fds;
        // fds.fd = NETMAP_FD(s->p);
        // fds.events = POLLIN;
        // poll(&fds, 1, -1);
        // goto retry;
        //
    }

    i = ring->cur;
    idx = ring->slot[i].buf_idx;
    pkt = (const uint8_t *)NETMAP_BUF(ring, idx);

    slot->pkthdr.ts = ring->ts;
    slot->pkthdr.len = slot->pkthdr.caplen = ring->slot[i].len;
    slot->pkthdr.buf_idx = idx;

    ring->slot[i].buf_idx = s->free_ring[s->free_head & s->free_mask];
    s->free_head++;
    ring->slot[i].flags |= NS_BUF_CHANGED;

    ring->head = ring->cur = nm_ring_next(ring, i);

    if (!nethuns_socket(s)->filter || nethuns_socket(s)->filter(nethuns_socket(s)->filter_ctx, &slot->pkthdr, pkt))
    {
        bytes = MIN(caplen, slot->pkthdr.caplen);

        slot->pkthdr.caplen = bytes;

        __atomic_store_n(&slot->inuse, 1, __ATOMIC_RELEASE);

        *pkthdr  = &slot->pkthdr;
        *payload =  pkt;

        return ++s->base.rx_ring.head;
    }

    nethuns_ring_free_slots(&s->base.rx_ring, nethuns_blocks_free, s);

    return 0;
}

int
nethuns_send_netmap(struct nethuns_socket_netmap *s, uint8_t const *packet, unsigned int len)
{
    struct nethuns_socket_base *b = nethuns_socket(s);
    struct nethuns_ring_slot *slot = nethuns_ring_get_slot(&b->tx_ring,
            b->tx_ring.tail);
    uint8_t *dst;

    if (__atomic_load_n(&slot->inuse, __ATOMIC_RELAXED))
        return -1;
    dst = nethuns_get_buf_addr_netmap(s, b->tx_ring.tail);
    nm_pkt_copy(packet, dst, len);
    nethuns_send_slot(s, b->tx_ring.tail, len);
    b->tx_ring.tail++;
    return 1;
}


int
nethuns_flush_netmap(struct nethuns_socket_netmap *s)
{
    unsigned int i;
    uint32_t *prev_tails;
    struct nethuns_socket_base *b = nethuns_socket(s);
    uint64_t head = b->tx_ring.head;
    struct nethuns_ring_slot *slot = nethuns_ring_get_slot(&b->tx_ring, head);
    struct netmap_ring *ring;
    struct netmap_slot *nslot;
    uint32_t buf_idx;

    prev_tails = alloca((s->p->last_tx_ring - s->p->first_tx_ring + 1) * sizeof(*prev_tails));

    // try to push packets marked for transmission
    for (i = s->p->first_tx_ring; i <= s->p->last_tx_ring; i++)
    {
        ring = NETMAP_TXRING(s->p->nifp, i);
        prev_tails[i] = ring->tail;

        while (!nm_ring_empty(ring) && __atomic_load_n(&slot->inuse, __ATOMIC_ACQUIRE) == 1)
        {
            // swap buf indexes between the nethuns and netmap slots, mark
            // the nethuns slot as in-flight (inuse <- 2)
            __atomic_store_n(&slot->inuse, 2, __ATOMIC_RELAXED);
            nslot = &ring->slot[ring->head];
            buf_idx = nslot->buf_idx;
            nslot->buf_idx = slot->pkthdr.buf_idx;
            slot->pkthdr.buf_idx = buf_idx;
            nslot->len = slot->len;
            nslot->flags = NS_BUF_CHANGED;
            // remember the nethuns slot in the netmap slot ptr field
            nslot->ptr = (uint64_t)slot;

            ring->head = ring->cur = nm_ring_next(ring, ring->head);
            b->tx_ring.head = ++head;
            slot = nethuns_ring_get_slot(&b->tx_ring, head);
       }
    }
    if (ioctl(s->p->fd, NIOCTXSYNC) < 0)
        return -1;
    // cleanup completed transmissions: for each completed
    // netmap slot, mark the corresponding nethuns slot as
    // available (inuse <- 0)
    for (i = s->p->first_tx_ring; i <= s->p->last_tx_ring; i++)
    {
        uint32_t scan, stop;
        ring = NETMAP_TXRING(s->p->nifp, i);

        stop = nm_ring_next(ring, ring->tail);
        for (scan = nm_ring_next(ring, prev_tails[i]); scan != stop;
                scan = nm_ring_next(ring, scan))
        {
            nslot = &ring->slot[scan];
            slot = (struct nethuns_ring_slot *)nslot->ptr;
            buf_idx = nslot->buf_idx;
            nslot->buf_idx = slot->pkthdr.buf_idx;
            slot->pkthdr.buf_idx = buf_idx;
            __atomic_store_n(&slot->inuse, 0, __ATOMIC_RELEASE);
        }
    }
    return 0;
}


int
nethuns_stats_netmap(__maybe_unused struct nethuns_socket_netmap *s, __maybe_unused struct nethuns_stat *stats)
{
#if 0
    stats->rx_packets    = s->p->st.ps_recv;
    stats->tx_packets    = 0;
    stats->rx_dropped    = s->p->st.ps_drop;
    stats->rx_if_dropped = s->p->st.ps_ifdrop;
    stats->rx_invalid    = 0;
    stats->tx_invalid    = 0;
    stats->freeze        = 0;
#endif
    return 0;
}


int
nethuns_fanout_netmap(__maybe_unused struct nethuns_socket_netmap *s, __maybe_unused int group, __maybe_unused const char *fanout)
{
    return -1;
}


int nethuns_fd_netmap(__maybe_unused struct nethuns_socket_netmap *s)
{
    return s->p ? s->p->fd : -1;
}


void
nethuns_dump_rings_netmap(__maybe_unused struct nethuns_socket_netmap *s)
{
}

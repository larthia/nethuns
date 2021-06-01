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
    struct nethuns_socket_netmap *sock;

    sock = calloc(1, sizeof(struct nethuns_socket_netmap));
    if (!sock)
    {
        nethuns_perror(errbuf, "open: could not allocate socket");
        return NULL;
    }

    if (nethuns_make_ring(opt->numblocks * opt->numpackets, opt->packetsize, &sock->base.rx_ring) < 0)
    {
        nethuns_perror(errbuf, "open: failed to allocate ring");
        free(sock);
        return NULL;
    }

    /* set a single consumer by default */

    sock->base.opt = *opt;
    return sock;
}


int nethuns_close_netmap(struct nethuns_socket_netmap *s)
{
    struct netmap_if *nifp;
    uint32_t idx, *next;

    if (s)
    {
        if (nethuns_socket(s)->opt.promisc)
        {
            __nethuns_clear_if_promisc(s, nethuns_socket(s)->devname);
        }

        nifp = s->p->nifp;
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
    char nm_dev[128];
    uint32_t extra_bufs;
    uint32_t scan;

    if (queue == NETHUNS_ANY_QUEUE)
    {
        snprintf(nm_dev, 128, "netmap:%s", dev);
    }
    else
    {
        snprintf(nm_dev, 128, "netmap:%s-%d", dev, nethuns_socket(s)->queue);
    }

    s->p = nmport_prepare(nm_dev);
    if (!s->p)
    {
        nethuns_perror(s->base.errbuf, "bind: could not open dev: %s", nethuns_dev_queue_name(dev, queue));
        return -1;
    }


    nethuns_socket(s)->queue   = queue;
    nethuns_socket(s)->ifindex = (int)if_nametoindex(dev);

    s->p->reg.nr_extra_bufs = s->base.rx_ring.size;

    if (nmport_open_desc(s->p) < 0) {
        nethuns_perror(s->base.errbuf, "open: could open dev %s (%s)", nethuns_dev_queue_name(dev, queue),
			strerror(errno));
        return -1;
    }

    if (s->p->reg.nr_extra_bufs != s->base.rx_ring.size) {
        nethuns_perror(s->base.errbuf, "dev %s: cannot obtain %u extra bufs (got %u)",
			nethuns_dev_queue_name(dev, queue),
                	s->base.rx_ring.size, s->p->reg.nr_extra_bufs);
        return -1;
    }

    s->some_ring = NETMAP_RXRING(s->p->nifp, s->p->first_rx_ring);

    extra_bufs = nethuns_lpow2(s->p->reg.nr_extra_bufs);
    s->free_ring = calloc(1, sizeof(uint32_t) * extra_bufs);
    if (!s->free_ring)
    {
        nethuns_perror(s->base.errbuf, "dev %s: out-of-memory while allocating free bufs list",
			nethuns_dev_queue_name(dev, queue));
        return -1;
    }
    s->free_mask = extra_bufs - 1;

    for (scan = s->p->nifp->ni_bufs_head; scan; scan = *(uint32_t *)NETMAP_BUF(s->some_ring, scan))
    {
        s->free_ring[s->free_tail & s->free_mask] = scan;
        s->free_tail++;
    }
    s->p->nifp->ni_bufs_head = 0;


    nethuns_socket(s)->devname = strdup(dev);

    if (nethuns_socket(s)->opt.promisc)
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
non_empty_ring(struct nmport_d *d)
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

    ring = non_empty_ring(s->p);
    if (unlikely(!ring))
    {
        ioctl(s->p->fd, NIOCRXSYNC);
        ring = non_empty_ring(s->p);
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
    return nmport_inject(s->p, packet, len);
}


int
nethuns_flush_netmap(struct nethuns_socket_netmap *s)
{
    return ioctl(s->p->fd, NIOCTXSYNC);
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

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

    if (nethuns_make_ring(opt->numblocks * opt->numpackets, opt->packetsize, &sock->base.ring) < 0)
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
    if (s)
    {
        if (nethuns_socket(s)->opt.promisc)
        {
            __nethuns_clear_if_promisc(s, nethuns_socket(s)->devname);
        }

        nm_close(s->p);

        __nethuns_free_base(s);
        free(s);
    }
    return 0;
}


int nethuns_bind_netmap(struct nethuns_socket_netmap *s, const char *dev, int queue)
{
    char nm_dev[128];

    nethuns_socket(s)->queue = queue;

    if (queue == NETHUNS_ANY_QUEUE)
    {
        snprintf(nm_dev, 128, "netmap:%s", dev);
    }
    else
    {
        snprintf(nm_dev, 128, "netmap:%s-%d", dev, nethuns_socket(s)->queue);
    }

    s->p = nm_open(nm_dev, NULL, 0, NULL);
    if (!s->p)
    {
        nethuns_perror(s->base.errbuf, "bind: could not open dev: %s", nethuns_dev_queue_name(dev, queue));
        return -1;
    }

    nethuns_socket(s)->queue   = queue;
    nethuns_socket(s)->ifindex = (int)if_nametoindex(dev);
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


uint64_t
nethuns_recv_netmap(struct nethuns_socket_netmap *s, nethuns_pkthdr_t const **pkthdr, uint8_t const **payload)
{
    unsigned int caplen = s->base.opt.packetsize;
    unsigned int bytes;
    const uint8_t *pkt;
    struct nm_pkthdr header;

    struct nethuns_ring_slot * slot = nethuns_ring_get_slot(&s->base.ring, s->base.ring.head);
    if (__atomic_load_n(&slot->inuse, __ATOMIC_ACQUIRE))
    {
        return 0;
    }

    pkt = nm_nextpkt(s->p, &header);
    if (unlikely(!pkt))
    {
        ioctl(s->p->fd, NIOCRXSYNC);
        pkt = nm_nextpkt(s->p, &header);
        if (unlikely(!pkt))
            return 0;

        //
        // struct pollfd fds;
        // fds.fd = NETMAP_FD(s->p);
        // fds.events = POLLIN;
        // poll(&fds, 1, -1);
        // goto retry;
        //
    }

    if (!nethuns_socket(s)->filter || nethuns_socket(s)->filter(nethuns_socket(s)->filter_ctx, &header, pkt))
    {
        bytes = MIN(caplen, header.caplen);

        memcpy(&slot->pkthdr, &header, sizeof(slot->pkthdr));
        memcpy(slot->packet, pkt, bytes);
        slot->pkthdr.caplen = bytes;

        __atomic_store_n(&slot->inuse, 1, __ATOMIC_RELEASE);

        *pkthdr  = &slot->pkthdr;
        *payload =  slot->packet;

        return ++s->base.ring.head;
    }

    return 0;
}


int
nethuns_send_netmap(struct nethuns_socket_netmap *s, uint8_t const *packet, unsigned int len)
{
    int n = nm_inject(s->p, packet, len);
    if (likely(n > 0)) {
        return n;
    }
    return -1;
}


int
nethuns_flush_netmap(struct nethuns_socket_netmap *s)
{
    return ioctl(s->p->fd, NIOCTXSYNC);
}


int
nethuns_stats_netmap(struct nethuns_socket_netmap *s, struct nethuns_stat *stats)
{
    stats->rx_packets    = s->p->st.ps_recv;
    stats->tx_packets    = 0;
    stats->rx_dropped    = s->p->st.ps_drop;
    stats->rx_if_dropped = s->p->st.ps_ifdrop;
    stats->rx_invalid    = 0;
    stats->tx_invalid    = 0;
    stats->freeze        = 0;
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

#include "../nethuns.h"
#include "compiler.h"
#include "netmap.h"
#include "ring.h"

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
    sock->base.clear_promisc = false;

    return sock;
}


int nethuns_close_netmap(struct nethuns_socket_netmap *s)
{
    if (s)
    {
        if (nethuns_base(s)->clear_promisc)
        {
            __nethuns_clear_if_promisc(s, nethuns_base(s)->devname);
        }

        nm_close(s->p);

        __nethuns_free_base(s);
        free(s);
    }
    return 0;
}


int nethuns_bind_netmap(struct nethuns_socket_netmap *s, const char *dev)
{
    char nm_dev[128];

    snprintf(nm_dev, 128, "netmap:%s", dev);

    s->p = nm_open(nm_dev, NULL, 0, NULL);
    if (!s->p)
    {
        nethuns_perror(s->base.errbuf, "open: could open dev %s (%s)", dev, strerror(errno));
        return -1;
    }

    nethuns_base(s)->devname = strdup(dev);

    if (nethuns_base(s)->opt.promisc)
    {
        if (__nethuns_set_if_promisc(s, nethuns_base(s)->devname) < 0)
            return -1;
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
        return 0;

        //
        // struct pollfd fds;
        // fds.fd = NETMAP_FD(s->p);
        // fds.events = POLLIN;
        // poll(&fds, 1, -1);
        // goto retry;
        //
    }

    bytes = MIN(caplen, header.caplen);

    memcpy(&slot->pkthdr, &header, sizeof(slot->pkthdr));
    memcpy(slot->packet, pkt, bytes);
    slot->pkthdr.caplen = bytes;

    __atomic_store_n(&slot->inuse, 1, __ATOMIC_RELEASE);

    *pkthdr  = &slot->pkthdr;
    *payload =  slot->packet;

    return ++s->base.ring.head;
}


int
nethuns_send_netmap(struct nethuns_socket_netmap *s, uint8_t const *packet, unsigned int len)
{
    return nm_inject(s->p, packet, len);
}


int
nethuns_flush_netmap(__maybe_unused struct nethuns_socket_netmap *s)
{
    return 0;
}


int
nethuns_get_stats_netmap(struct nethuns_socket_netmap *s, struct nethuns_stats *stats)
{
    stats->packets = s->p->st.ps_recv;
    stats->drops   = s->p->st.ps_drop;
    stats->ifdrops = s->p->st.ps_ifdrop;
    stats->freeze  = 0;
    return 0;
}


int
nethuns_fanout_netmap(__maybe_unused struct nethuns_socket_netmap *s, __maybe_unused int group, __maybe_unused const char *fanout)
{
    return -1;
}


int nethuns_fd_netmap(__maybe_unused struct nethuns_socket_netmap *s)
{
    return s->p->fd;
}


void
nethuns_dump_rings_netmap(__maybe_unused struct nethuns_socket_netmap *s)
{
}



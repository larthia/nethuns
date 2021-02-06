#include "../nethuns.h"
#include "../util/macro.h"
#include "../util/compiler.h"

#include "libpcap.h"
#include "ring.h"

#include <pcap/pcap.h>
#include <sys/ioctl.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>


struct nethuns_socket_libpcap *
nethuns_open_libpcap(struct nethuns_socket_options *opt, char *errbuf)
{
    struct nethuns_socket_libpcap *sock;

    sock = calloc(1, sizeof(struct nethuns_socket_libpcap));
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


int nethuns_close_libpcap(struct nethuns_socket_libpcap *s)
{
    if (s && s->p)
    {
        pcap_close(s->p);

        __nethuns_free_base(s);

        free(s);
    }
    return 0;
}


int nethuns_bind_libpcap(struct nethuns_socket_libpcap *s, const char *dev, int queue)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    if (queue != NETHUNS_ANY_QUEUE)
    {
        nethuns_perror(nethuns_socket(s)->errbuf, "open: only ANY_QUEUE is currently supported by this device");
        return -1;
    }

    nethuns_socket(s)->queue = NETHUNS_ANY_QUEUE;

    s->p = pcap_create(dev, errbuf);
    if (!s->p) {
        nethuns_perror(s->base.errbuf, "bind: %s", errbuf);
        return -1;
    }

    if (pcap_set_immediate_mode(s->p, 1) != 0)
    {
        nethuns_perror(s->base.errbuf, "bind: %s", pcap_geterr(s->p));
        return -1;
    }

    if (pcap_set_buffer_size(s->p, (int)(nethuns_socket(s)->opt.numblocks * nethuns_socket(s)->opt.numpackets * nethuns_socket(s)->opt.packetsize)) != 0)
    {
        nethuns_perror(s->base.errbuf, "bind: %s", pcap_geterr(s->p));
        return -1;
    }

    if (nethuns_socket(s)->opt.promisc)
    {
        if (pcap_set_promisc(s->p, 1) != 0)
        {
            nethuns_perror(s->base.errbuf, "bind: %s", pcap_geterr(s->p));
            return -1;
        }
    }

    if (pcap_set_snaplen(s->p, (int)nethuns_socket(s)->opt.packetsize) != 0)
    {
        nethuns_perror(s->base.errbuf, "bind: %s", pcap_geterr(s->p));
        return -1;
    }

    if (pcap_set_timeout(s->p, (int)nethuns_socket(s)->opt.timeout_ms) != 0)
    {
        nethuns_perror(s->base.errbuf, "bind: %s", pcap_geterr(s->p));
        return -1;
    }

    if (pcap_activate(s->p) != 0)
    {
        nethuns_perror(s->base.errbuf, "bind: %s", pcap_geterr(s->p));
        return -1;
    }

    if (pcap_setnonblock(s->p, 1, errbuf) < 0)
    {
        nethuns_perror(s->base.errbuf, "bind: %s", errbuf);
        return -1;
    }

    switch (nethuns_socket(s)->opt.dir)
    {
        case nethuns_in: {
            if (pcap_setdirection(s->p, PCAP_D_IN) < 0)
            {
                nethuns_perror(s->base.errbuf, "bind: dir_in %s", pcap_geterr(s->p));
                return -1;
            }
        } break;
        case nethuns_out: {
            if (pcap_setdirection(s->p, PCAP_D_OUT) < 0)
            {
                nethuns_perror(s->base.errbuf, "bind: dir_out %s", pcap_geterr(s->p));
                return -1;
            }
        } break;
        case nethuns_in_out:
        {
            if (pcap_setdirection(s->p, PCAP_D_INOUT) < 0)
            {
                nethuns_perror(s->base.errbuf, "bind: dir_inout %s", pcap_geterr(s->p));
                return -1;
            }
        }
    }

    return 0;
}


uint64_t
nethuns_recv_libpcap(struct nethuns_socket_libpcap *s, nethuns_pkthdr_t const **pkthdr, uint8_t const **payload)
{
    unsigned int caplen = nethuns_socket(s)->opt.packetsize;
    unsigned int bytes;
    const uint8_t *ppayload;

    struct pcap_pkthdr header;

    struct nethuns_ring_slot * slot = nethuns_get_ring_slot(&s->base.ring, s->base.ring.head);

#if 1
    if (s->p == NULL || __atomic_load_n(&slot->inuse, __ATOMIC_ACQUIRE))
    {
        return 0;
    }
#else
    if ((p->base.ring.head - p->base.ring.tail) == (p->base.ring.size-1))
    {
        nethuns_ring_free_id(&p->base.ring, CALLBACK, ARG);
        if ((p->base.ring.head - p->base.ring.tail) == (p->base.ring.size-1))
            return 0;
    }
#endif

    ppayload = pcap_next(s->p, &header);

    bytes = MIN(caplen, header.caplen);

    if (ppayload)
    {
        if (!nethuns_socket(s)->filter || nethuns_socket(s)->filter(nethuns_socket(s)->filter_ctx, &header, ppayload))
        {
            memcpy(&slot->pkthdr, &header, sizeof(slot->pkthdr));
            memcpy(slot->packet, ppayload, bytes);
            slot->pkthdr.caplen = bytes;

            __atomic_store_n(&slot->inuse, 1, __ATOMIC_RELEASE);

            *pkthdr  = &slot->pkthdr;
            *payload =  slot->packet;

            return ++s->base.ring.head;
        }
    }

    return 0;
}


int
nethuns_send_libpcap(struct nethuns_socket_libpcap *s, uint8_t const *packet, unsigned int len)
{
    if (likely(s->p != NULL)) {
    	return pcap_inject(s->p, packet, len);
    }
    return -1;
}


int
nethuns_flush_libpcap(__maybe_unused struct nethuns_socket_libpcap *s)
{
    return 0;
}


int
nethuns_stats_libpcap(struct nethuns_socket_libpcap *s, struct nethuns_stat *stats)
{
    struct pcap_stat ps;
    if (s->p == NULL || pcap_stats(s->p, &ps) == -1)
    {
        return -1;
    }

    stats->rx_packets    = ps.ps_recv;
    stats->tx_packets    = 0;
    stats->rx_dropped    = ps.ps_drop;
    stats->rx_if_dropped = ps.ps_ifdrop;
    stats->rx_invalid    = 0;
    stats->tx_invalid    = 0;
    stats->freeze        = 0;
    return 0;
}


int
nethuns_fanout_libpcap(__maybe_unused struct nethuns_socket_libpcap *s, __maybe_unused int group, __maybe_unused const char *fanout)
{
    return -1;
}


int nethuns_fd_libpcap(__maybe_unused struct nethuns_socket_libpcap *s)
{
    return -1;
}


void
nethuns_dump_rings_libpcap(__maybe_unused struct nethuns_socket_libpcap *s)
{
}




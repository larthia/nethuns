#include "../nethuns.h"
#include "compiler.h"
#include "devpcap.h"
#include "ring.h"

#include <pcap/pcap.h>
#include <sys/ioctl.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>


struct nethuns_socket_devpcap *
nethuns_open_devpcap(struct nethuns_socket_options *opt, int queue, char *errbuf)
{
    struct nethuns_socket_devpcap *sock;

    if (queue != NETHUNS_ANY_QUEUE)
    {
        nethuns_perror(errbuf, "open: only ANY_QUEUE is currently supported by this device");
        return NULL;
    }

    sock = calloc(1, sizeof(struct nethuns_socket_devpcap));
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


int nethuns_close_devpcap(struct nethuns_socket_devpcap *s)
{
    if (s)
    {
        pcap_close(s->p);

        __nethuns_free_base(s);

        free(s);
    }
    return 0;
}


int nethuns_bind_devpcap(struct nethuns_socket_devpcap *s, const char *dev)
{
    char errbuf[PCAP_ERRBUF_SIZE];

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

    if (pcap_set_buffer_size(s->p, (int)(nethuns_base(s)->opt.numblocks * nethuns_base(s)->opt.numpackets * nethuns_base(s)->opt.packetsize)) != 0)
    {
        nethuns_perror(s->base.errbuf, "bind: %s", pcap_geterr(s->p));
        return -1;
    }

    if (nethuns_base(s)->opt.promisc)
    {
        if (pcap_set_promisc(s->p, 1) != 0)
        {
            nethuns_perror(s->base.errbuf, "bind: %s", pcap_geterr(s->p));
            return -1;
        }
    }

    if (pcap_set_snaplen(s->p, (int)nethuns_base(s)->opt.packetsize) != 0)
    {
        nethuns_perror(s->base.errbuf, "bind: %s", pcap_geterr(s->p));
        return -1;
    }

    if (pcap_set_timeout(s->p, (int)nethuns_base(s)->opt.timeout_ms) != 0)
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

    switch (nethuns_base(s)->opt.dir)
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
nethuns_recv_devpcap(struct nethuns_socket_devpcap *s, nethuns_pkthdr_t const **pkthdr, uint8_t const **payload)
{
    unsigned int caplen = nethuns_base(s)->opt.packetsize;
    unsigned int bytes;
    const uint8_t *ppayload;

    struct pcap_pkthdr header;

    struct nethuns_ring_slot * slot = nethuns_ring_get_slot(&s->base.ring, s->base.ring.head);

#if 1
    if (__atomic_load_n(&slot->inuse, __ATOMIC_ACQUIRE))
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
        memcpy(&slot->pkthdr, &header, sizeof(slot->pkthdr));
        memcpy(slot->packet, ppayload, bytes);
        slot->pkthdr.caplen = bytes;

        __atomic_store_n(&slot->inuse, 1, __ATOMIC_RELEASE);

        *pkthdr  = &slot->pkthdr;
        *payload =  slot->packet;

        return ++s->base.ring.head;
    }

    return 0;
}


int
nethuns_send_devpcap(struct nethuns_socket_devpcap *s, uint8_t const *packet, unsigned int len)
{
    return pcap_inject(s->p, packet, len);
}


int
nethuns_flush_devpcap(__maybe_unused struct nethuns_socket_devpcap *s)
{
    return 0;
}


int
nethuns_get_stats_devpcap(struct nethuns_socket_devpcap *s, struct nethuns_stats *stats)
{
    struct pcap_stat ps;
    if (pcap_stats(s->p, &ps) == -1)
    {
        return -1;
    }

    stats->packets = ps.ps_recv;
    stats->drops   = ps.ps_drop;
    stats->ifdrops = ps.ps_ifdrop;
    stats->freeze  = 0;
    return 0;
}


int
nethuns_fanout_devpcap(__maybe_unused struct nethuns_socket_devpcap *s, __maybe_unused int group, __maybe_unused const char *fanout)
{
    return -1;
}


int nethuns_fd_devpcap(__maybe_unused struct nethuns_socket_devpcap *s)
{
    return -1;
}


void
nethuns_dump_rings_devpcap(__maybe_unused struct nethuns_socket_devpcap *s)
{
}




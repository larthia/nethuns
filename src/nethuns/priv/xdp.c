#include "../nethuns.h"
#include "compiler.h"
#include "xdp.h"
#include "ring.h"

#include <sys/ioctl.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <bpf.h>
#include <xsk.h>


struct nethuns_socket_xdp *
nethuns_open_xdp(struct nethuns_socket_options *opt, char *errbuf)
{
    struct nethuns_socket_xdp *sock;

    sock = calloc(1, sizeof(struct nethuns_socket_xdp));
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


int nethuns_close_xdp(struct nethuns_socket_xdp *s)
{
    if (s)
    {
        // pcap_close(s->p);

        __nethuns_free_base(s);

        free(s);
    }
    return 0;
}


int nethuns_bind_xdp(struct nethuns_socket_xdp *s, const char *dev, int queue)
{
    char errbuf[1024];

    if (queue != NETHUNS_ANY_QUEUE)
    {
        nethuns_perror(nethuns_data(s)->errbuf, "open: only ANY_QUEUE is currently supported by this device");
        return -1;
    }

    nethuns_data(s)->queue = NETHUNS_ANY_QUEUE;

    // s->p = pcap_create(dev, errbuf);
    // if (!s->p) {
    //     nethuns_perror(s->base.errbuf, "bind: %s", errbuf);
    //     return -1;
    // }

    // if (pcap_set_immediate_mode(s->p, 1) != 0)
    // {
    //     nethuns_perror(s->base.errbuf, "bind: %s", pcap_geterr(s->p));
    //     return -1;
    // }

    // if (pcap_set_buffer_size(s->p, (int)(nethuns_data(s)->opt.numblocks * nethuns_data(s)->opt.numpackets * nethuns_data(s)->opt.packetsize)) != 0)
    // {
    //     nethuns_perror(s->base.errbuf, "bind: %s", pcap_geterr(s->p));
    //     return -1;
    // }

    // if (nethuns_data(s)->opt.promisc)
    // {
    //     if (pcap_set_promisc(s->p, 1) != 0)
    //     {
    //         nethuns_perror(s->base.errbuf, "bind: %s", pcap_geterr(s->p));
    //         return -1;
    //     }
    // }

    // if (pcap_set_snaplen(s->p, (int)nethuns_data(s)->opt.packetsize) != 0)
    // {
    //     nethuns_perror(s->base.errbuf, "bind: %s", pcap_geterr(s->p));
    //     return -1;
    // }

    // if (pcap_set_timeout(s->p, (int)nethuns_data(s)->opt.timeout_ms) != 0)
    // {
    //     nethuns_perror(s->base.errbuf, "bind: %s", pcap_geterr(s->p));
    //     return -1;
    // }

    // if (pcap_activate(s->p) != 0)
    // {
    //     nethuns_perror(s->base.errbuf, "bind: %s", pcap_geterr(s->p));
    //     return -1;
    // }

    // if (pcap_setnonblock(s->p, 1, errbuf) < 0)
    // {
    //     nethuns_perror(s->base.errbuf, "bind: %s", errbuf);
    //     return -1;
    // }

    // switch (nethuns_data(s)->opt.dir)
    // {
    //     case nethuns_in: {
    //         if (pcap_setdirection(s->p, PCAP_D_IN) < 0)
    //         {
    //             nethuns_perror(s->base.errbuf, "bind: dir_in %s", pcap_geterr(s->p));
    //             return -1;
    //         }
    //     } break;
    //     case nethuns_out: {
    //         if (pcap_setdirection(s->p, PCAP_D_OUT) < 0)
    //         {
    //             nethuns_perror(s->base.errbuf, "bind: dir_out %s", pcap_geterr(s->p));
    //             return -1;
    //         }
    //     } break;
    //     case nethuns_in_out:
    //     {
    //         if (pcap_setdirection(s->p, PCAP_D_INOUT) < 0)
    //         {
    //             nethuns_perror(s->base.errbuf, "bind: dir_inout %s", pcap_geterr(s->p));
    //             return -1;
    //         }
    //     }
    // }

    return 0;
}


uint64_t
nethuns_recv_xdp(struct nethuns_socket_xdp *s, nethuns_pkthdr_t const **pkthdr, uint8_t const **payload)
{
    unsigned int caplen = nethuns_data(s)->opt.packetsize;
    unsigned int bytes;
    const uint8_t *ppayload;

    // struct pcap_pkthdr header;

    struct nethuns_ring_slot * slot = nethuns_get_ring_slot(&s->base.ring, s->base.ring.head);

    if (__atomic_load_n(&slot->inuse, __ATOMIC_ACQUIRE))
    {
        return 0;
    }

    // ppayload = pcap_next(s->p, &header);

    // bytes = MIN(caplen, header.caplen);

    // if (ppayload)
    // {
    //     if (!nethuns_data(s)->filter || nethuns_data(s)->filter(nethuns_data(s)->filter_ctx, &header, ppayload))
    //     {
    //         memcpy(&slot->pkthdr, &header, sizeof(slot->pkthdr));
    //         memcpy(slot->packet, ppayload, bytes);
    //         slot->pkthdr.caplen = bytes;

    //         __atomic_store_n(&slot->inuse, 1, __ATOMIC_RELEASE);

    //         *pkthdr  = &slot->pkthdr;
    //         *payload =  slot->packet;

    //         return ++s->base.ring.head;
    //     }
    // }

    return 0;
}


int
nethuns_send_xdp(struct nethuns_socket_xdp *s, uint8_t const *packet, unsigned int len)
{
    // return pcap_inject(s->p, packet, len);
    return 0;
}


int
nethuns_flush_xdp(__maybe_unused struct nethuns_socket_xdp *s)
{
    return 0;
}


int
nethuns_stats_xdp(struct nethuns_socket_xdp *s, struct nethuns_stats *stats)
{
    // struct pcap_stat ps;
    // if (pcap_stats(s->p, &ps) == -1)
    // {
    //     return -1;
    // }

    stats->packets = 0;
    stats->drops   = 0;
    stats->ifdrops = 0;
    stats->freeze  = 0;
    return 0;
}


int
nethuns_fanout_xdp(__maybe_unused struct nethuns_socket_xdp *s, __maybe_unused int group, __maybe_unused const char *fanout)
{
    return -1;
}


int nethuns_fd_xdp(__maybe_unused struct nethuns_socket_xdp *s)
{
    return -1;
}


void
nethuns_dump_rings_xdp(__maybe_unused struct nethuns_socket_xdp *s)
{
}


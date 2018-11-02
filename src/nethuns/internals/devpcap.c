#include "nethuns_base.h"
#include "compiler.h"
#include "devpcap.h"
#include "ring.h"

#include <pcap/pcap.h>
#include <sys/ioctl.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

struct nethuns_socket_devpcap *
nethuns_open_devpcap(struct nethuns_socket_options *opt, char *errbuf)
{
    struct  nethuns_ring *ring = NULL;
    struct nethuns_socket_devpcap *sock;

    ring = nethuns_make_ring(opt->numblocks * opt->numpackets, opt->packetsize);
    if (!ring)
    {
        nethuns_perror(errbuf, "nethuns_open: failed to allocate ring");
        return NULL;
    }

    sock = malloc(sizeof(struct nethuns_socket_devpcap));
    memset(sock, 0, sizeof(*sock));

    /* set a single consumer by default */

    sock->base.sync.number = 1;
    sock->base.opt = *opt;
    sock->ring     = ring;
    sock->idx      = 0;
    sock->idx_rls  = 0;

    return sock;
}


int nethuns_close_devpcap(struct nethuns_socket_devpcap *s)
{
    if (s)
    {
        pcap_close(s->p);
        free(s->ring);
        free(s);
    }
    return 0;
}


int nethuns_bind_devpcap(struct nethuns_socket_devpcap *s, const char *dev)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    s->p = pcap_create(dev, errbuf);
    if (!s->p) {
        nethuns_perror(s->base.errbuf, errbuf);
        return -1;
    }

    if (pcap_set_immediate_mode(s->p, 1) != 0)
    {
        nethuns_perror(s->base.errbuf, pcap_geterr(s->p));
    }

    if (pcap_set_buffer_size(s->p, (int)(s->base.opt.numblocks * s->base.opt.numpackets * s->base.opt.packetsize)) != 0)
    {
        nethuns_perror(s->base.errbuf, pcap_geterr(s->p));
    }

    if (pcap_set_promisc(s->p, 1) != 0)
    {
        nethuns_perror(s->base.errbuf, pcap_geterr(s->p));
    }

    if (pcap_set_snaplen(s->p, (int)s->base.opt.packetsize) != 0)
    {
        nethuns_perror(s->base.errbuf, pcap_geterr(s->p));
    }

    if (pcap_set_timeout(s->p, (int)s->base.opt.timeout_ms) != 0)
    {
        nethuns_perror(s->base.errbuf, pcap_geterr(s->p));
    }

    if (pcap_setnonblock(s->p, 1, errbuf) < 0)
    {
        nethuns_perror(s->base.errbuf, errbuf);
    }

    if (pcap_setdirection(s->p, PCAP_D_IN) < 0)
    {
        nethuns_perror(s->base.errbuf, pcap_geterr(s->p));
    }

    if (pcap_activate(s->p) != 0)
    {
        nethuns_perror(s->base.errbuf, pcap_geterr(s->p));
    }

    return 0;
}


static int
__nethus_devpcap_packets_release(struct nethuns_socket_devpcap *p)
{
    uint64_t rid = p->idx_rls;
    unsigned int i;

    uint64_t cur = nethuns_synpse_min(&p->base.sync);

    for(; rid < cur; ++rid)
    {
        struct nethuns_ring_slot * slot = nethuns_ring_slot_mod(p->ring, rid);
        slot->inuse = 0;
    }

    p->idx_rls = rid;
    return 0;
}


uint64_t
nethuns_recv_devpcap(struct nethuns_socket_devpcap *s, nethuns_pkthdr_t const **pkthdr, uint8_t const **payload)
{
    unsigned int caplen = s->base.opt.packetsize;
    unsigned int bytes;
    const uint8_t *ppayload;

    struct pcap_pkthdr header;

    struct nethuns_ring_slot * slot = nethuns_ring_slot_mod(s->ring, s->idx);

    if (slot->inuse)
    {
        __nethus_devpcap_packets_release(s);
        return 0;
    }

    ppayload = pcap_next(s->p, &header);

    bytes = MIN(caplen, header.caplen);

    if (ppayload)
    {
        memcpy(&slot->pkthdr, &header, sizeof(slot->pkthdr));
        memcpy(slot->packet, ppayload, bytes);
        slot->pkthdr.caplen = bytes;

        slot->inuse = 1;

        *pkthdr  = &slot->pkthdr;
        *payload =  slot->packet;
        s->idx++;
        return s->idx;
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




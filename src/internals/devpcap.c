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
    sock->ring = ring;
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


int nethuns_fd_devpcap(struct nethuns_socket_devpcap *s)
{
    return -1;
}


static int
__nethuns_blocks_release_devpcap(struct nethuns_socket_devpcap *s)
{
#if 0
    uint64_t rid = s->rx_block_idx_rls, cur = UINT64_MAX;
    unsigned int i;

    for(i = 0; i < s->base.sync.number; i++)
        cur = MIN(cur, __atomic_load_n(&s->base.sync.id[i].value, __ATOMIC_ACQUIRE));

    for(; rid < cur; ++rid)
    {
        struct block_descr_v3 *pb = __nethuns_block_mod_devpcap(&s->rx_ring, rid);
        pb->hdr.block_status = TP_STATUS_KERNEL;
    }

    s->rx_block_idx_rls = rid;
#endif

    return 0;
}


uint64_t
nethuns_recv_devpcap(struct nethuns_socket_devpcap *s, nethuns_pkthdr_t **pkthdr, uint8_t const **pkt)
{
    return 0;
}

int
nethuns_flush_devpcap(__maybe_unused struct nethuns_socket_devpcap *s)
{
    return 0;
}


int
nethuns_send_devpcap(struct nethuns_socket_devpcap *s, uint8_t const *packet, unsigned int len)
{
    return 1;
}


int
nethuns_get_stats_devpcap(struct nethuns_socket_devpcap *s, struct nethuns_stats *stats)
{
    return 0;
}


int
nethuns_fanout_devpcap(__maybe_unused struct nethuns_socket_devpcap *s, __maybe_unused int group, __maybe_unused const char *fanout)
{
    return -1;
}


void
nethuns_dump_rings_devpcap(__maybe_unused struct nethuns_socket_devpcap *s)
{
}


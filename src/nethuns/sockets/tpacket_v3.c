#include "../nethuns.h"
#include "../util/compiler.h"
#include "../util/macro.h"

#include "tpacket_v3.h"
#include "ring.h"

#include <linux/version.h>

#include <sys/ioctl.h>
#include <net/if.h>

#include <poll.h>
#include <errno.h>
#include <string.h>

struct nethuns_socket_tpacket_v3 *
nethuns_open_tpacket_v3(struct nethuns_socket_options *opt, char *errbuf)
{
    struct nethuns_socket_tpacket_v3 * sock;
    int fd, err, v = TPACKET_V3;
    unsigned int i;

    fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd == -1) {
        nethuns_perror(errbuf, "open");
        return NULL;
    }

    err = setsockopt(fd, SOL_PACKET, PACKET_VERSION, &v, sizeof(v));
    if (err < 0) {
        nethuns_perror(errbuf, "unsupported PACKET_VERSION");
        close(fd);
        return NULL;
    }

    sock = calloc(1, sizeof(struct nethuns_socket_tpacket_v3));
    if (!sock)
    {
        nethuns_perror(errbuf, "open: could not allocate socket");
        close(fd);
        return NULL;
    }

    sock->rx_ring.req.tp_block_size     = opt->numpackets * opt->packetsize;
    sock->rx_ring.req.tp_frame_size     = opt->packetsize;
    sock->rx_ring.req.tp_block_nr       = opt->numblocks;
    sock->rx_ring.req.tp_frame_nr       = opt->numblocks * opt->numpackets;
    sock->rx_ring.req.tp_retire_blk_tov = opt->timeout_ms;
    sock->rx_ring.req.tp_sizeof_priv    = 0;
    sock->rx_ring.req.tp_feature_req_word = opt->rxhash ? TP_FT_REQ_FILL_RXHASH : 0;

    err = setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &sock->rx_ring.req, sizeof(sock->rx_ring.req));
    if (err < 0) {
        nethuns_perror(errbuf, "setsockopt RX_RING");
        free(sock);
        close(fd);
        return NULL;
    }

    sock->tx_ring.req.tp_block_size     = opt->numpackets * opt->packetsize;
    sock->tx_ring.req.tp_frame_size     = opt->packetsize;
    sock->tx_ring.req.tp_block_nr       = opt->numblocks;
    sock->tx_ring.req.tp_frame_nr       = opt->numblocks * opt->numpackets;

    err = setsockopt(fd, SOL_PACKET, PACKET_TX_RING, &sock->tx_ring.req, sizeof(sock->tx_ring.req));
    if (err < 0) {
        nethuns_perror(errbuf, "setsockopt TX_RING");
        free(sock);
        close(fd);
        return NULL;
    }

    /* map memory */

    sock->rx_ring.map = mmap( NULL
                            , (sock->rx_ring.req.tp_block_size * sock->rx_ring.req.tp_block_nr) +
                              (sock->tx_ring.req.tp_block_size * sock->tx_ring.req.tp_block_nr)
                            , PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED | MAP_POPULATE, fd, 0);

    if (sock->rx_ring.map == MAP_FAILED) {
        nethuns_perror(errbuf, "mmap");
        free(sock);
        close(fd);
        return NULL;
    }

    sock->tx_ring.map = sock->rx_ring.map + (sock->rx_ring.req.tp_block_size * sock->rx_ring.req.tp_block_nr);

    /* setup Rx ring... */

    sock->rx_ring.rd = calloc(1, sock->rx_ring.req.tp_block_nr * sizeof(*(sock->rx_ring.rd)));
    if (!sock->rx_ring.rd)
    {
        munmap(sock->rx_ring.map, sock->rx_ring.req.tp_block_size * sock->rx_ring.req.tp_block_nr +
                                  sock->tx_ring.req.tp_block_size * sock->tx_ring.req.tp_block_nr);
        free(sock);
        close(fd);
        return NULL;
    }

    for (i = 0; i < sock->rx_ring.req.tp_block_nr; ++i) {
        sock->rx_ring.rd[i].iov_base = sock->rx_ring.map + (i * sock->rx_ring.req.tp_block_size);
        sock->rx_ring.rd[i].iov_len  = sock->rx_ring.req.tp_block_size;
    }

    /* setup Tx ring... */

    sock->tx_ring.rd = calloc(1, sock->tx_ring.req.tp_block_nr * sizeof(*(sock->tx_ring.rd)));
    if (!sock->tx_ring.rd)
    {
        free(sock->rx_ring.rd);
        munmap(sock->rx_ring.map, sock->rx_ring.req.tp_block_size * sock->rx_ring.req.tp_block_nr +
                                  sock->tx_ring.req.tp_block_size * sock->tx_ring.req.tp_block_nr);
        free(sock);
        close(fd);
        return NULL;
    }

    for (i = 0; i < sock->tx_ring.req.tp_block_nr; ++i) {
        sock->tx_ring.rd[i].iov_base = sock->tx_ring.map + (i * sock->tx_ring.req.tp_block_size);
        sock->tx_ring.rd[i].iov_len  = sock->tx_ring.req.tp_block_size;
    }

    /* QDISC bypass */

    if (opt->tx_qdisc_bypass)
    {
        int one = 1;
        setsockopt(fd, SOL_PACKET, PACKET_QDISC_BYPASS, &one, sizeof(one));
    }

    if (nethuns_make_ring(opt->numblocks * opt->numpackets * opt->packetsize / 16, 0, &sock->base.ring) < 0)
    {
        nethuns_perror(errbuf, "ring: could not allocate ring");
        free(sock->rx_ring.rd);
        free(sock->tx_ring.rd);
        munmap(sock->rx_ring.map, sock->rx_ring.req.tp_block_size * sock->rx_ring.req.tp_block_nr +
                                  sock->tx_ring.req.tp_block_size * sock->tx_ring.req.tp_block_nr);
        free(sock);
        close(fd);
        return NULL;
    }

    sock->base.opt          = *opt;
    sock->fd                = fd;

    sock->rx_block_idx_rls  = 0;
    sock->rx_block_idx      = 0;
    sock->rx_block_mod      = 0;

    sock->tx_block_idx_rls  = 0;
    sock->tx_block_idx      = 0;
    sock->tx_block_mod      = 0;

    sock->rx_frame_idx      = 0;
    sock->tx_frame_idx      = 0;

    sock->rx_pfd.fd         = fd;
    sock->rx_pfd.events     = POLLIN | POLLERR;
    sock->rx_pfd.revents    = 0;

    sock->tx_pfd.fd         = fd;
    sock->tx_pfd.events     = POLLOUT | POLLERR;
    sock->tx_pfd.revents    = 0;

    return sock;
}


int nethuns_close_tpacket_v3(struct nethuns_socket_tpacket_v3 *s)
{
    if (s)
    {
        if (nethuns_socket(s)->opt.promisc)
        {
            __nethuns_clear_if_promisc(s, nethuns_socket(s)->devname);
        }
        free(s->tx_ring.rd);
        free(s->rx_ring.rd);
        munmap(s->rx_ring.map, s->rx_ring.req.tp_block_size * s->rx_ring.req.tp_block_nr +
                               s->tx_ring.req.tp_block_size * s->tx_ring.req.tp_block_nr);
        close(s->fd);
        __nethuns_free_base(s);
        free(s);
    }
    return 0;
}


int nethuns_bind_tpacket_v3(struct nethuns_socket_tpacket_v3 *s, const char *dev, int queue)
{
    struct sockaddr_ll addr;
    int err;

    if (queue != NETHUNS_ANY_QUEUE)
    {
        nethuns_perror(nethuns_socket(s)->errbuf, "open: only ANY_QUEUE is currently supported by this device");
        return -1;
    }

    nethuns_socket(s)->queue = NETHUNS_ANY_QUEUE;

    memset(&addr, 0, sizeof(addr));

    addr.sll_family   = AF_PACKET;
    addr.sll_protocol = ntohs(ETH_P_ALL);
    nethuns_socket(s)->ifindex = addr.sll_ifindex = (int)if_nametoindex(dev);

    if (!addr.sll_ifindex) {
        nethuns_perror(s->base.errbuf, "if_nametoindex %s", dev);
        return -1;
    }

    err = bind(s->fd, (struct sockaddr *)&addr, sizeof(addr));
    if (err < 0) {
        nethuns_perror(s->base.errbuf, "bind %s", dev);
        return -1;
    }

    /* save device name.. */

    nethuns_socket(s)->queue   = queue;
    nethuns_socket(s)->ifindex = (int)if_nametoindex(dev);
    nethuns_socket(s)->devname = strdup(dev);

    /* set promisc interface */

    if (nethuns_socket(s)->opt.promisc)
    {
        if (__nethuns_set_if_promisc(s, dev) < 0)
            return -1;
    }

    return 0;
}


int nethuns_fd_tpacket_v3(struct nethuns_socket_tpacket_v3 *s)
{
    return s->fd;
}


static int
__nethuns_blocks_free(__maybe_unused struct nethuns_ring_slot *slot,  uint64_t blockid, void *user)
{
    struct nethuns_socket_tpacket_v3 * s = (struct nethuns_socket_tpacket_v3 *)user;
    uint64_t rid = s->rx_block_idx_rls;

    while ((blockid - rid) > 1)
    {
        struct block_descr_v3 *pb = __nethuns_block_mod_tpacket_v3(&s->rx_ring, rid);
        pb->hdr.block_status = TP_STATUS_KERNEL;
        ++rid;
    }

    s->rx_block_idx_rls = rid;
    return 0;
}


uint64_t
nethuns_recv_tpacket_v3(struct nethuns_socket_tpacket_v3 *s, nethuns_pkthdr_t const **pkthdr, uint8_t const **pkt)
{
    struct block_descr_v3 * pb;

    pb = __nethuns_block_tpacket_v3(&s->rx_ring, s->rx_block_mod);

    if (unlikely(  (pb->hdr.block_status & TP_STATUS_USER) == 0                      /* real ring is full or.. */
                || (s->base.ring.head - s->base.ring.tail) == (s->base.ring.size-1)  /* virtual ring is full   */
                ))
    {
        nethuns_ring_free_slots(&s->base.ring, __nethuns_blocks_free, s);
        // poll(&s->rx_pfd, 1, -1);
        return 0;
    }

    if (likely(s->rx_frame_idx < pb->hdr.num_pkts))
    {
        struct nethuns_ring_slot *slot;

        if (unlikely(s->rx_frame_idx++ == 0))
        {
            s->rx_ppd = (struct tpacket3_hdr *) ((uint8_t *) pb + pb->hdr.offset_to_first_pkt);
        }

        struct sockaddr_ll *sll = (struct sockaddr_ll *)((uint8_t *)s->rx_ppd + TPACKET_ALIGN(sizeof(struct tpacket3_hdr)));


        if ((s->base.opt.dir == nethuns_in_out)                                     ||
            (s->base.opt.dir == nethuns_in  && sll->sll_pkttype != PACKET_OUTGOING) ||
            (s->base.opt.dir == nethuns_out && sll->sll_pkttype == PACKET_OUTGOING))
        {
            *pkthdr    = s->rx_ppd;
            *pkt       = (uint8_t *)(s->rx_ppd) + s->rx_ppd->tp_mac;

            if (!nethuns_socket(s)->filter || nethuns_socket(s)->filter(nethuns_socket(s)->filter_ctx, *pkthdr, *pkt))
            {
                s->rx_ppd  = (struct tpacket3_hdr *) ((uint8_t *) s->rx_ppd + s->rx_ppd->tp_next_offset);

                slot = nethuns_ring_next_slot(&s->base.ring);
                slot->id = s->rx_block_idx;
                __atomic_store_n(&slot->inuse, 1, __ATOMIC_RELEASE);

                return s->base.ring.head;
            }
        }

        /* discard this packet */
        s->rx_ppd  = (struct tpacket3_hdr *) ((uint8_t *) s->rx_ppd + s->rx_ppd->tp_next_offset);
        return 0;
    }

    nethuns_ring_free_slots(&s->base.ring, __nethuns_blocks_free, s);

    s->rx_block_idx++;
    s->rx_block_mod = (s->rx_block_mod + 1) % s->rx_ring.req.tp_block_nr;
    s->rx_frame_idx = 0;

    return 0;
}


static inline int
__nethuns_flush_tpacket_v3(struct nethuns_socket_tpacket_v3 *s)
{
    if (sendto(s->fd, NULL, 0, 0, NULL, 0) < 0) {
        nethuns_perror(s->base.errbuf, "flush");
        return -1;
    }

    return 0;
}


int
nethuns_flush_tpacket_v3(struct nethuns_socket_tpacket_v3 *s)
{
    return __nethuns_flush_tpacket_v3(s);
}


int
nethuns_send_tpacket_v3(struct nethuns_socket_tpacket_v3 *s, uint8_t const *packet, unsigned int len)
{
    const size_t numpackets = s->tx_ring.req.tp_block_size/s->tx_ring.req.tp_frame_size;

    uint8_t *pbase;

    if (s->tx_frame_idx == numpackets)
    {
        if (nethuns_flush_tpacket_v3(s) < 0)
        {
            return -1;
        }

        s->tx_block_idx++;
        s->tx_block_mod = (s->tx_block_mod + 1) % s->tx_ring.req.tp_block_nr;
        s->tx_frame_idx = 0;
    }
    else if (s->base.opt.timeout_ms == 0)
    {
        nethuns_flush_tpacket_v3(s);
    }

    pbase = (uint8_t *)__nethuns_block_tpacket_v3(&s->tx_ring, s->tx_block_mod);

    struct tpacket3_hdr * tx = (struct tpacket3_hdr *)(pbase + s->tx_frame_idx * s->tx_ring.req.tp_frame_size);

    if (unlikely(tx->tp_status & (TP_STATUS_SEND_REQUEST | TP_STATUS_SENDING)))
    {
        poll(&s->tx_pfd, 1, 1);
        return 0;
    }

    tx->tp_snaplen     = len;
    tx->tp_len         = len;
    tx->tp_next_offset = 0;

    memcpy((uint8_t *)tx + TPACKET3_HDRLEN - sizeof(struct sockaddr_ll), packet, len);

    tx->tp_status = TP_STATUS_SEND_REQUEST;

    __sync_synchronize();

    s->tx_frame_idx++;
    return len;
}



static inline
int __fanout_code(int strategy, int defrag, int rollover)
{
    if (defrag)   strategy |= PACKET_FANOUT_FLAG_DEFRAG;
    if (rollover) strategy |= PACKET_FANOUT_FLAG_ROLLOVER;
    return strategy;
}


static int
__parse_fanout(const char *str)
{
    int defrag = 0, rollover = 0;

    if (!str) return -1;

    /* parse options */

    if (strcasestr(str, "|defrag"))
        defrag = 1;

    if (strcasestr(str, "|rollover"))
        rollover = 1;

    /* parse strategy */

#define _(x)  x, (sizeof(x)-1)

#ifdef PACKET_FANOUT_DATA
    if (strncasecmp(str, _("data")) == 0)
        return __fanout_code(PACKET_FANOUT_DATA, defrag, rollover);
#endif
#ifdef PACKET_FANOUT_HASH
    if (strncasecmp(str, _("hash")) == 0)
        return __fanout_code(PACKET_FANOUT_HASH, defrag, rollover);
#endif
#ifdef PACKET_FANOUT_LB
    if (strncasecmp(str, _("lb")) == 0)
        return __fanout_code(PACKET_FANOUT_LB, defrag, rollover);
#endif
#ifdef PACKET_FANOUT_CPU
    if (strncasecmp(str, _("cpu")) == 0)
        return __fanout_code(PACKET_FANOUT_CPU, defrag, rollover);
#endif
#ifdef PACKET_FANOUT_ROLLOVER
    if (strncasecmp(str, _("rollover")) == 0)
            return __fanout_code(PACKET_FANOUT_ROLLOVER, defrag, rollover);
#endif
#ifdef PACKET_FANOUT_RND
    if (strncasecmp(str, _("rnd")) == 0)
            return __fanout_code(PACKET_FANOUT_RND, defrag, rollover);
#endif
#ifdef PACKET_FANOUT_QM
    if (strncasecmp(str, _("qm")) == 0)
            return __fanout_code(PACKET_FANOUT_QM, defrag, rollover);
#endif
#ifdef PACKET_FANOUT_CBPF
    if (strncasecmp(str, _("cbpf")) == 0)
            return __fanout_code(PACKET_FANOUT_CBPF, defrag, rollover);
#endif
#ifdef PACKET_FANOUT_EBPF
    if (strncasecmp(str, _("ebpf")) == 0)
        return __fanout_code(PACKET_FANOUT_EBPF, defrag, rollover);
#endif
#undef _

    return -1;
}


int
nethuns_fanout_tpacket_v3(struct nethuns_socket_tpacket_v3 *s, int group, const char *fanout)
{
    int fanout_code, fanout_arg;
    int err;

    fanout_code = __parse_fanout(fanout);
    if (fanout_code < 0) {
        nethuns_perror(s->base.errbuf, "parse_fanout");
        return -1;
    }

    fanout_arg = group | (fanout_code << 16);

    err = setsockopt(s->fd, SOL_PACKET, PACKET_FANOUT, &fanout_arg, sizeof(fanout_arg));
    if (err) {
        nethuns_perror(s->base.errbuf, "fanout");
        return -1;
    }

    return 0;
}


void
__dump_ring(struct ring_v3 *ring, const char *label)
{
    fprintf(stderr, "%s {", label);
    unsigned int n;
    for(n = 0; n < ring->req.tp_block_nr; ++n)
    {
        struct block_descr_v3 * pb;
        pb = __nethuns_block_tpacket_v3(ring, n);
        fprintf(stderr, "%x[%u] ", pb->hdr.block_status
                     , pb->hdr.num_pkts);
    }
    fprintf(stderr, "} ");
}

void
nethuns_dump_rings_tpacket_v3(struct nethuns_socket_tpacket_v3 *s)
{
    __dump_ring(&s->rx_ring, "rx");
    __dump_ring(&s->tx_ring, "tx");
    fprintf(stderr, "\n");
}


int
nethuns_stats_tpacket_v3(struct nethuns_socket_tpacket_v3 *s, struct nethuns_stat *stats)
{
    struct tpacket_stats_v3 _stats;
    socklen_t len = sizeof(_stats);

    if (getsockopt(s->fd, SOL_PACKET, PACKET_STATISTICS, &_stats, &len) < 0)
    {
        nethuns_perror(s->base.errbuf, "stats");
        return -1;
    }

    stats->rx_packets    = _stats.tp_packets;
    stats->rx_dropped    = _stats.tp_drops;
    stats->freeze        = _stats.tp_freeze_q_cnt;
    stats->tx_packets    = 0;
    stats->rx_if_dropped = 0;
    stats->rx_invalid    = 0;
    stats->tx_invalid    = 0;

    return 0;
}

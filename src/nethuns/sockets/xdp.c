#include "../nethuns.h"
#include "../util/compiler.h"
#include "xdp.h"
#include "ring.h"

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <net/if.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <linux/bpf.h>
#include <src/libbpf.h>

#include <linux/if_link.h>
#include <linux/if_xdp.h>

#include "xdp/xsk_ext.h"

static int
load_xdp_program(struct nethuns_socket_xdp *s, const char *dev)
{
    nethuns_lock_global();

    struct nethuns_netinfo *info = nethuns_lookup_netinfo(dev);
    if (info == NULL) {
        info = nethuns_create_netinfo(dev);
        if (info == NULL) {
            goto err;
        }
    }

    if (info->xdp_prog_refcnt++ == 0) {

        struct bpf_prog_load_attr prog_load_attr = {
            .prog_type      = BPF_PROG_TYPE_XDP,
            .file           = nethuns_socket(s)->opt.xdp_prog,
        };

        int prog_fd;

        nethuns_fprintf(stderr, "bpf_prog_load: loading %s program...\n", nethuns_socket(s)->opt.xdp_prog);

        if (bpf_prog_load_xattr(&prog_load_attr, &s->obj, &prog_fd)) {
            nethuns_perror(nethuns_socket(s)->errbuf, "bpf_prog_load: could not load %s program", nethuns_socket(s)->opt.xdp_prog);
            goto err;
        }

        if (prog_fd < 0) {
            nethuns_perror(nethuns_socket(s)->errbuf, "bpf_prog_load: no program found: %s", strerror(prog_fd));
            goto err;
        }

        if (bpf_set_link_xdp_fd(nethuns_socket(s)->ifindex, prog_fd, s->xdp_flags) < 0) {
            nethuns_perror(nethuns_socket(s)->errbuf, "bpf_set_link_fd: set link xpd failed");
            goto err;
        }

        // retrieve the actual xdp program id...
        //

        if (bpf_get_link_xdp_id(nethuns_socket(s)->ifindex, &info->xdp_prog_id, s->xdp_flags))
        {
            nethuns_perror(nethuns_socket(s)->errbuf, "bpf_get_link_id: get link xpd failed");
            goto err;
        }

        nethuns_fprintf(stderr, "bpf_prog_load: done\n");
    }

    nethuns_unlock_global();
    return 0;
err:
    nethuns_unlock_global();
    return -1;
}


static int
unload_xdp_program(struct nethuns_socket_xdp *s)
{
    uint32_t curr_prog_id = 0;

    nethuns_lock_global();

    struct nethuns_netinfo *info = nethuns_lookup_netinfo(nethuns_socket(s)->devname);
    if (info != NULL) {
        if (--info->xdp_prog_refcnt == 0)
        {
            nethuns_fprintf(stderr, "bpf_prog_load: unloading %s program...\n", nethuns_socket(s)->opt.xdp_prog);

            if (bpf_get_link_xdp_id(nethuns_socket(s)->ifindex, &curr_prog_id, s->xdp_flags)) {
                nethuns_perror(nethuns_socket(s)->errbuf, "bpf_get_link: could get xdp id");
                goto err;
            }

            if (info->xdp_prog_id == curr_prog_id) {
	            bpf_set_link_xdp_fd(nethuns_socket(s)->ifindex, -1, s->xdp_flags);

            } else if (!curr_prog_id) {
                nethuns_perror(nethuns_socket(s)->errbuf, "bpf_prog: could get find a prog id on dev '%s'", nethuns_socket(s)->devname);
                goto err;
            } else {
                nethuns_perror(nethuns_socket(s)->errbuf, "bpf_prog: program on dev '%s' changed?", nethuns_socket(s)->devname);
                goto err;
            }

            nethuns_fprintf(stderr, "bpf_prog_load: done\n");
        }
    } else {
        nethuns_perror(nethuns_socket(s)->errbuf, "unload_xdp_program: could not find dev '%s'", nethuns_socket(s)->devname);
        goto err;
    }

    nethuns_unlock_global();
    return 0;
  err:
    nethuns_unlock_global();
    return -1;
}


struct nethuns_socket_xdp *
nethuns_open_xdp(struct nethuns_socket_options *opt, char *errbuf)
{
    struct nethuns_socket_xdp *s;
    int n;

    s = calloc(1, sizeof(struct nethuns_socket_xdp));
    if (!s)
    {
        nethuns_perror(errbuf, "open: could not allocate socket");
        return NULL;
    }

    if (nethuns_make_ring(opt->numblocks * opt->numpackets, opt->packetsize, &s->base.ring) < 0)
    {
        nethuns_perror(errbuf, "open: failed to allocate ring");
        free(s);
        return NULL;
    }

    /* set defualt xdp_flags */

    s->xdp_flags = 0; // or safer XDP_FLAGS_UPDATE_IF_NOEXIST;
    s->xdp_bind_flags = 0; // XDP_USE_NEED_WAKEUP;

    switch(opt->capture)
    {
    case nethuns_cap_default: {
    	s->xdp_flags |= XDP_FLAGS_SKB_MODE;
    	s->xdp_bind_flags |= XDP_COPY;
    } break;
    case nethuns_cap_skb_mode: {
    	s->xdp_flags |= XDP_FLAGS_SKB_MODE;
    	s->xdp_bind_flags |= XDP_COPY;
    } break;
    case nethuns_cap_drv_mode: {
    	s->xdp_flags |= XDP_FLAGS_DRV_MODE;
    	s->xdp_bind_flags |= XDP_COPY;
    } break;
    case nethuns_cap_zero_copy: {
    	s->xdp_flags |= XDP_FLAGS_DRV_MODE;
    	s->xdp_bind_flags |= XDP_ZEROCOPY;
    }
    }

    nethuns_socket(s)->ifindex = 0;

    // TODO: support for HUGE pages
    // -> opt_umem_flags |= XDP_UMEM_UNALIGNED_CHUNK_FLAG;

    // adjust packet size...
    //

    static const size_t size_[] = {2048, 4096};
    for (n = 0; n < sizeof(size_)/sizeof(size_[0]); n++)
    {
        if (opt->packetsize <= size_[n]) {
            opt->packetsize = size_[n];
            break;
        }
    }

    if (n == sizeof(size_)/sizeof(size_[0])) {
        nethuns_perror(errbuf, "open: XDP packet size too large!");
        goto err0;
    }

    s->total_mem = opt->numblocks * opt->numpackets * opt->packetsize;

    s->bufs = mmap(NULL, s->total_mem,
                                 PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS /* | MAP_HUGETLB */, -1, 0);

    if (s->bufs == MAP_FAILED) {
        nethuns_perror(errbuf, "open: XDP bufs mmap failed");
        goto err0;
    }

	s->umem = xsk_configure_umem(s, s->bufs, s->total_mem, opt->packetsize);
    if (!s->umem) {
        nethuns_perror(errbuf, "open: XDP configure umem failed!");
        goto err1;
    }

    s->rx = false;
    s->tx = false;

    if (opt->mode == nethuns_socket_rx_tx || opt->mode == nethuns_socket_rx_only) {
        s->rx = true;
    }

    if (opt->mode == nethuns_socket_rx_tx || opt->mode == nethuns_socket_tx_only) {
        s->tx = true;
    }

    // postpone the creation of the socket to bind stage...

    s->xsk = NULL;

    nethuns_socket(s)->opt = *opt;
    return s;

    err1:
        munmap(s->bufs, s->total_mem);
    err0:
        free(s);
        return NULL;
    }

int nethuns_close_xdp(struct nethuns_socket_xdp *s)
{
    if (s)
    {
        if (s->xsk)  {
            xsk_socket__delete(s->xsk->xsk);
        }

        xsk_umem__delete(s->umem->umem);
        munmap(s->bufs, s->total_mem);


        if (nethuns_socket(s)->opt.xdp_prog) {
            unload_xdp_program(s);
        }

        if (nethuns_socket(s)->opt.promisc)
        {
            __nethuns_clear_if_promisc(s, nethuns_socket(s)->devname);
        }

        __nethuns_free_base(s);
        free(s);
    }
    return 0;
}


int nethuns_bind_xdp(struct nethuns_socket_xdp *s, const char *dev, int queue)
{
    if (queue == NETHUNS_ANY_QUEUE)
    {
        nethuns_fprintf(stderr, "bind: ANY_QUEUE is not supported by XDP device -> reverting to queue 0\n");
        queue = 0;
    }

    nethuns_socket(s)->queue   = queue;
    nethuns_socket(s)->ifindex = (int)if_nametoindex(dev);
    nethuns_socket(s)->devname = strdup(dev);

    // actually open the xsk socket here...

    s->xsk = xsk_configure_socket(s, nethuns_socket(s)->opt.numpackets, nethuns_socket(s)->opt.packetsize, s->rx, s->tx);
    if (!s->xsk) {
        return -1;
    }

    if (nethuns_socket(s)->opt.xdp_prog) {
        if (load_xdp_program(s, dev) < 0) {
    	    return -1;
        }

        if (xsk_enter_into_map(s) < 0) {
            return -1;
        }
    }

    if (nethuns_socket(s)->opt.promisc)
    {
        if (__nethuns_set_if_promisc(s, dev) < 0)
            return -1;
    }

    return 0;
}


static int
__nethuns_xdp_free_slots(struct nethuns_ring_slot *slot, __maybe_unused uint64_t id, void *user)
{
    struct nethuns_socket_xdp *s = (struct nethuns_socket_xdp *)user;
    xsk_ring_cons__release(&s->xsk->rx, 1);
    return 0;
}


uint64_t
nethuns_recv_xdp(struct nethuns_socket_xdp *s, nethuns_pkthdr_t const **pkthdr, uint8_t const **payload)
{
    unsigned int caplen = nethuns_socket(s)->opt.packetsize;
    uint32_t idx_rx = 0, idx_fq = 0;
    int rcvd, ret;
    unsigned int i, stock_frames;

    nethuns_ring_free_slots(&s->base.ring, __nethuns_xdp_free_slots, s);

    struct nethuns_ring_slot * slot = nethuns_get_ring_slot(&s->base.ring, s->base.ring.head);
    if (__atomic_load_n(&slot->inuse, __ATOMIC_ACQUIRE))
    {
        return 0;
    }

    // retrieve the pointer to the packet
    //

    rcvd = xsk_ring_cons__peek(&s->xsk->rx, 1, &idx_rx);
    if (rcvd == 0)  {
        return 0;
    }

    stock_frames = xsk_prod_nb_free(&s->xsk->umem->fq, xsk_umem_free_frames(s->xsk));
    if (stock_frames > 0) {

        ret = xsk_ring_prod__reserve(&s->xsk->umem->fq, stock_frames, &idx_fq);

        while (ret != rcvd)
			ret = xsk_ring_prod__reserve(&s->xsk->umem->fq, rcvd, &idx_fq);

        for (i = 0; i < stock_frames; i++)
			*xsk_ring_prod__fill_addr(&s->xsk->umem->fq, idx_fq++) =
				xsk_alloc_umem_frame(s->xsk);

		xsk_ring_prod__submit(&s->xsk->umem->fq, stock_frames);
    }

    /* process the packet */

	uint64_t addr = xsk_ring_cons__rx_desc(&s->xsk->rx, idx_rx)->addr;
	uint32_t len  = xsk_ring_cons__rx_desc(&s->xsk->rx, idx_rx)->len;
	uint64_t orig = xsk_umem__extract_addr(addr);

	addr = xsk_umem__add_offset_to_addr(addr);
	unsigned char *pkt = xsk_umem__get_data(s->xsk->umem->buffer, addr);

    __atomic_add_fetch(&s->xsk->rx_npkts, 1, __ATOMIC_RELAXED);

    // get timestamp...

    struct timespec tp;
    clock_gettime(CLOCK_MONOTONIC_COARSE, &tp);

    struct xdp_pkthdr header = {
        .sec     = (int32_t)tp.tv_sec
      , .nsec    = (int32_t)tp.tv_nsec
      , .len     = len
      , .snaplen = len
    };

    if (!nethuns_socket(s)->filter || nethuns_socket(s)->filter(nethuns_socket(s)->filter_ctx, &header, pkt))
    {
        memcpy(&slot->pkthdr, &header, sizeof(slot->pkthdr));

        slot->orig   = orig;
        slot->idx_fq = idx_fq;
        slot->packet = pkt;

        __atomic_store_n(&slot->inuse, 1, __ATOMIC_RELEASE);

        *pkthdr  = &slot->pkthdr;
        *payload =  slot->packet;
        return ++s->base.ring.head;
    }

    return 0;
}


int
nethuns_send_xdp(struct nethuns_socket_xdp *s, uint8_t const *packet, unsigned int len)
{
    // return pcap_inject(s->p, packet, len);
    return -1;
}


int
nethuns_flush_xdp(__maybe_unused struct nethuns_socket_xdp *s)
{
    return 0;
}


int
nethuns_stats_xdp(struct nethuns_socket_xdp *s, struct nethuns_stat *stats)
{
    struct xdp_statistics xdp_stats;

    if (likely(s->xsk != NULL))
    {
        socklen_t len = sizeof(xdp_stats);

        stats->rx_packets = __atomic_load_n(&s->xsk->rx_npkts, __ATOMIC_RELAXED);
        stats->tx_packets = __atomic_load_n(&s->xsk->tx_npkts, __ATOMIC_RELAXED);

        if (getsockopt(xsk_socket__fd(s->xsk->xsk), SOL_XDP, XDP_STATISTICS, &xdp_stats, &len) == 0) {
            stats->rx_dropped = xdp_stats.rx_dropped;
            stats->rx_invalid = xdp_stats.rx_invalid_descs;
            stats->tx_invalid = xdp_stats.tx_invalid_descs;
        } else {
            stats->rx_dropped = 0;
            stats->rx_invalid = 0;
            stats->tx_invalid = 0;
        }
    }
    else {
        stats->rx_packets = 0;
        stats->tx_packets = 0;
        stats->rx_invalid = 0;
        stats->tx_invalid = 0;
        stats->rx_dropped = 0;
    }

    stats->rx_if_dropped = 0;
    stats->freeze        = 0;
    return 0;
}


int nethuns_fd_xdp(__maybe_unused struct nethuns_socket_xdp *s)
{
    return xsk_socket__fd(s->xsk->xsk);
}


int
nethuns_fanout_xdp(__maybe_unused struct nethuns_socket_xdp *s, __maybe_unused int group, __maybe_unused const char *fanout)
{
    return -1;
}


void
nethuns_dump_rings_xdp(__maybe_unused struct nethuns_socket_xdp *s)
{
}

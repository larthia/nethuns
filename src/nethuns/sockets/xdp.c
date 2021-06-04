#define NETHUNS_SOCKET NETHUNS_SOCKET_XDP
#include "ring.h"

#define SOCKET_TYPE xdp 
#include "file.inc"

#include "../misc/compiler.h"

#include "../api.h"
#include "xdp.h"
#include "xsk_ext.h"

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

	if (prog_load_attr.file == NULL) {
	    nethuns_fprintf(stderr, "bpf_prog_load: using default program\n");
	    goto out;
	}

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
out:
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
            nethuns_fprintf(stderr, "bpf_prog_load: unloading %s program...\n", nethuns_socket(s)->opt.xdp_prog ? nethuns_socket(s)->opt.xdp_prog : "default");

            if (bpf_get_link_xdp_id(nethuns_socket(s)->ifindex, &curr_prog_id, s->xdp_flags)) {
                nethuns_perror(nethuns_socket(s)->errbuf, "bpf_get_link: could get xdp id");
                goto err;
            }

            if (info->xdp_prog_id == 0 || info->xdp_prog_id == curr_prog_id) {
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
    unsigned int n;

    s = calloc(1, sizeof(struct nethuns_socket_xdp));
    if (!s)
    {
        nethuns_perror(errbuf, "open: could not allocate socket");
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

    s->rx = false;
    s->tx = false;

    if (opt->mode == nethuns_socket_rx_tx || opt->mode == nethuns_socket_rx_only) {
        s->rx = true;
    }

    if (opt->mode == nethuns_socket_rx_tx || opt->mode == nethuns_socket_tx_only) {
        s->tx = true;
    }

	if (!s->rx && !s->tx) {
		nethuns_perror(errbuf, "open: please select at least one between rx and tx");
		goto err0;
	}

    // what is the purpose of numblock?
	s->first_rx_frame = 0;
	s->first_tx_frame = 0;
    if (s->rx) {
        if (nethuns_make_ring(opt->numblocks * opt->numpackets, 0, &s->base.rx_ring) < 0)
        {
            nethuns_perror(errbuf, "open: failed to allocate ring");
            goto err0;
        }
		s->first_tx_frame = s->base.rx_ring.mask + 1;
    }

    if (s->tx) {
        if (nethuns_make_ring(opt->numblocks * opt->numpackets, 0, &s->base.tx_ring) < 0)
        {
            nethuns_perror(errbuf, "open: failed to allocate ring");
            goto err1;
        }
    }
    s->framesz = nethuns_lpow2(opt->packetsize);
    s->fshift = __builtin_ctzl(s->framesz);

    s->total_mem = !!s->tx * (s->base.tx_ring.mask + 1) * s->framesz +
                   !!s->rx * (s->base.rx_ring.mask + 1) * s->framesz;

    s->bufs = mmap(NULL, s->total_mem,
                                 PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS /* | MAP_HUGETLB */, -1, 0);

    if (s->bufs == MAP_FAILED) {
        nethuns_perror(errbuf, "open: XDP bufs mmap failed");
        goto err1;
    }

	s->umem = xsk_configure_umem(s, s->bufs, s->total_mem, s->framesz);
    if (!s->umem) {
        nethuns_perror(errbuf, "open: XDP configure umem failed!");
        goto err2;
    }


    // postpone the creation of the socket to bind stage...

    s->xsk = NULL;

    nethuns_socket(s)->opt = *opt;
    return s;

    err2:
        munmap(s->bufs, s->total_mem);
    err1:
	    if (s->rx) {
	        nethuns_delete_ring(&s->base.rx_ring);
	    }
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


        unload_xdp_program(s);

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

    s->xsk = xsk_configure_socket(s);
    if (!s->xsk) {
        nethuns_perror(s->base.errbuf, "bind: configure socket (%s)", nethuns_dev_queue_name(dev, queue));
        return -1;
    }

    if (load_xdp_program(s, dev) < 0) {
        nethuns_perror(s->base.errbuf, "bind: could not load xdp program %s (%s)", nethuns_socket(s)->opt.xdp_prog, nethuns_dev_queue_name(dev, queue));
        return -1;
    }

    if (nethuns_socket(s)->opt.xdp_prog) {
        if (xsk_enter_into_map(s) < 0) {
            nethuns_perror(s->base.errbuf, "bind: could not enter into map (%s)", nethuns_dev_queue_name(dev, queue));
            return -1;
        }
    }

    if (nethuns_socket(s)->opt.promisc)
    {
        if (__nethuns_set_if_promisc(s, dev) < 0) {
            nethuns_perror(s->base.errbuf, "bind: could not set promisc (%s)", nethuns_dev_queue_name(dev, queue));
            return -1;
	}
    }

    nethuns_lock_global();

    struct nethuns_netinfo *info = nethuns_lookup_netinfo(dev);

    if (info->xdp_prog_id == 0) {
	// the library has loaded the default program, retrieve its id
        if (bpf_get_link_xdp_id(nethuns_socket(s)->ifindex, &info->xdp_prog_id, s->xdp_flags))
        {
            nethuns_perror(nethuns_socket(s)->errbuf, "bpf_get_link_id: get link xpd failed");
            nethuns_unlock_global();
	    return -1;
        }
    }

    nethuns_unlock_global();

    return 0;
}


static int
__nethuns_xdp_free_slots(struct nethuns_ring_slot *slot, __maybe_unused uint64_t id, void *user)
{
    struct nethuns_socket_xdp *s = (struct nethuns_socket_xdp *)user;
    xsk_ring_cons__release(&s->xsk->rx, 1);
    (void)slot;
    return 0;
}

uint64_t
nethuns_recv_xdp(struct nethuns_socket_xdp *s, nethuns_pkthdr_t const **pkthdr, uint8_t const **payload)
{
    // unsigned int caplen = nethuns_socket(s)->opt.packetsize;
    uint32_t idx_fq = 0;
    unsigned int ret;
    unsigned int i, stock_frames;

    nethuns_ring_free_slots(&s->base.rx_ring, __nethuns_xdp_free_slots, s);

    struct nethuns_ring_slot * slot = nethuns_ring_get_slot(&s->base.rx_ring, s->base.rx_ring.head);
    if (__atomic_load_n(&slot->inuse, __ATOMIC_ACQUIRE))
    {
        return 0;
    }

    // retrieve the pointer to the packet
    //

	if (s->rcvd == 0) {
		s->rcvd = xsk_ring_cons__peek(&s->xsk->rx, 1, &s->idx_rx);
		if (s->rcvd == 0)  {
			return 0;
		}

		stock_frames = xsk_prod_nb_free(&s->xsk->umem->fq, 16);
		if (stock_frames > 0) {

			ret = xsk_ring_prod__reserve(&s->xsk->umem->fq, stock_frames, &idx_fq);

			while (ret != stock_frames)
				ret = xsk_ring_prod__reserve(&s->xsk->umem->fq, s->rcvd, &idx_fq);

			for (i = 0; i < stock_frames; i++) {
				//printf("rx_frame(%d) %lx\n", idx_fq, rx_frame(s, idx_fq));
				*xsk_ring_prod__fill_addr(&s->xsk->umem->fq, idx_fq) = rx_frame(s, idx_fq);
				idx_fq++;
			}


			xsk_ring_prod__submit(&s->xsk->umem->fq, stock_frames);
		}
	}

    /* process the packet */

        uint64_t addr;
	slot->addr = addr = xsk_ring_cons__rx_desc(&s->xsk->rx, s->idx_rx)->addr;
	uint32_t len  = xsk_ring_cons__rx_desc(&s->xsk->rx, s->idx_rx++)->len;
	s->rcvd--;

	addr = xsk_umem__add_offset_to_addr(addr);
	unsigned char *pkt = xsk_umem__get_data(s->xsk->umem->buffer, addr);

    __atomic_add_fetch(&s->xsk->rx_npkts, 1, __ATOMIC_RELAXED);

    // get timestamp...

    struct timespec tp;
    //clock_gettime(CLOCK_MONOTONIC_COARSE, &tp);

    struct xdp_pkthdr header = {
        .sec     = (int32_t)tp.tv_sec
      , .nsec    = (int32_t)tp.tv_nsec
      , .len     = len
      , .snaplen = len
    };

    if (!nethuns_socket(s)->filter || nethuns_socket(s)->filter(nethuns_socket(s)->filter_ctx, &header, pkt))
    {
        memcpy(&slot->pkthdr, &header, sizeof(slot->pkthdr));

        slot->packet = pkt;

        __atomic_store_n(&slot->inuse, 1, __ATOMIC_RELEASE);

        *pkthdr  = &slot->pkthdr;
        *payload =  slot->packet;
        // TODO: this will give 0 when head wraps around
        return ++s->base.rx_ring.head;
    }

    return 0;
}

static void kick_tx(struct xsk_socket_info *xsk)
{
	int ret;

	ret = sendto(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
	if (ret >= 0 || errno == ENOBUFS || errno == EAGAIN || errno == EBUSY)
		return;
}


static void xdp_complete_tx(struct nethuns_socket_xdp *s)
{
	if (s->xsk->outstanding_tx > 0) {
		if (xsk_ring_prod__needs_wakeup(&s->xsk->tx))
			kick_tx(s->xsk);

//		int rcvd = xsk_ring_cons__peek(&s->xsk->umem->cq, XSK_RING_PROD__DEFAULT_NUM_DESCS, &dummy);
//		if (rcvd > 0) {
//			xsk_ring_cons__release(&s->xsk->umem->cq, rcvd);
//			s->xsk->outstanding_tx -= rcvd;
//		}
	}
}

uint8_t *
nethuns_get_buf_addr_xdp(struct nethuns_socket_xdp *s, uint64_t pktid)
{
    // XXX check pktid
    return xsk_umem__get_data(s->xsk->umem->buffer, tx_frame(s, pktid));
}

int
nethuns_send_xdp(struct nethuns_socket_xdp *s, uint8_t const *packet, unsigned int len)
{
    uint64_t tail = s->base.tx_ring.tail;
    struct nethuns_ring_slot *slot = nethuns_ring_get_slot(&s->base.tx_ring, tail);
	uint8_t *frame = xsk_umem__get_data(s->xsk->umem->buffer, tx_frame(s, tail));
  
    if (__atomic_load_n(&slot->inuse, __ATOMIC_RELAXED)) {
        return 0;
    }

    memcpy(frame, packet, len);
    s->base.tx_ring.tail++;
    nethuns_send_slot(s, tail, len);
    //printf("marking slot %d\n", tail);
	return 1;
}

int
nethuns_flush_xdp(struct nethuns_socket_xdp *s)
{
    uint32_t idx = 0;
    unsigned int cmpl, i, toflush;

    // mark completed transmissions
    cmpl = xsk_ring_cons__peek(&s->xsk->umem->cq, s->base.tx_ring.size, &idx);
    for (i = 0; i < cmpl; i++) {
        uint64_t addr = *xsk_ring_cons__comp_addr(&s->xsk->umem->cq, idx);
        uint64_t slotnr = tx_slot(s, addr);
        struct nethuns_ring_slot *slot = nethuns_ring_get_slot(&s->base.tx_ring, slotnr);
        //printf("release slot %lu addr %lx\n", slotnr, addr);
        __atomic_store_n(&slot->inuse, 0, __ATOMIC_RELEASE);
        idx++;
    }
	xsk_ring_cons__release(&s->xsk->umem->cq, cmpl);
	s->xsk->outstanding_tx -= cmpl;
    //printf("cmpl %d outstanding %d\n", cmpl, s->xsk->outstanding_tx);
    __atomic_add_fetch(&s->xsk->tx_npkts, cmpl, __ATOMIC_RELAXED);

    toflush = 0;
    for (i = 0; i < s->base.tx_ring.size; i++) {
        uint64_t head = s->base.tx_ring.head;
        struct nethuns_ring_slot *slot = nethuns_ring_get_slot(&s->base.tx_ring, head);
        if (__atomic_load_n(&slot->inuse, __ATOMIC_ACQUIRE) != 1)
            break;

        __atomic_store_n(&slot->inuse, 2, __ATOMIC_RELAXED);
        xsk_ring_prod__reserve(&s->xsk->tx, 1, &idx);
        xsk_ring_prod__tx_desc(&s->xsk->tx, idx)->addr = tx_frame(s, head);
        //printf("slot %d sending %lx\n", head, tx_frame(s, head));
        xsk_ring_prod__tx_desc(&s->xsk->tx, idx)->len = slot->len;
        toflush++;
        s->base.tx_ring.head++;
    }
	if (toflush) {
	    xsk_ring_prod__submit(&s->xsk->tx, toflush);
	    s->xsk->outstanding_tx += toflush;
        //printf("toflush %d outstanding %d\n", cmpl, s->xsk->outstanding_tx);
	    xdp_complete_tx(s);
    }
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
    nethuns_perror(s->base.errbuf, "fanout: not supported (%s)", nethuns_device_name(s));
    return -1;
}


void
nethuns_dump_rings_xdp(__maybe_unused struct nethuns_socket_xdp *s)
{
}

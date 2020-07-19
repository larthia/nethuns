#include "../nethuns.h"
#include "compiler.h"
#include "xdp.h"
#include "ring.h"

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <net/if.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <linux/bpf.h>
#include <src/libbpf.h>

#include <linux/if_link.h>
#include <linux/if_xdp.h>

#include "xdp/xsk_ext.h"

static int
load_xdp_program(struct nethuns_socket_xdp *sock)
{
    struct bpf_prog_load_attr prog_load_attr = {
        .prog_type      = BPF_PROG_TYPE_XDP,
        .file           = "/etc/nethuns/net_xdp.o"
    };

    int prog_fd;

    if (bpf_prog_load_xattr(&prog_load_attr, &sock->obj, &prog_fd)) {
        nethuns_perror(nethuns_socket(sock)->errbuf, "bpf_prog_load: could not load program");
        return -1;
    }

    if (prog_fd < 0) {
        nethuns_perror(nethuns_socket(sock)->errbuf, "bpf_prog_load: no program found: %s", strerror(prog_fd));
        return -1;
    }

    if (bpf_set_link_xdp_fd(nethuns_socket(sock)->ifindex, prog_fd, sock->xdp_flags) < 0) {
        nethuns_perror(nethuns_socket(sock)->errbuf, "bpf_set_link_fd: set link xpd failed");
        return -1;
    }

    // retrieve the actual xdp program id...
    //
    if (bpf_get_link_xdp_id(nethuns_socket(sock)->ifindex, &sock->prog_id, sock->xdp_flags)) {
        nethuns_perror(nethuns_socket(sock)->errbuf, "bpf_get_link_id: get link xpd failed");
	return -1;
    }

    return 0;
}


static int
unload_xdp_program(struct nethuns_socket_xdp *sock)
{
    uint32_t curr_prog_id = 0;

    if (bpf_get_link_xdp_id(nethuns_socket(sock)->ifindex, &curr_prog_id, sock->xdp_flags)) {
        nethuns_perror(nethuns_socket(sock)->errbuf, "bpf_get_link: could get xdp id");
        return -1;
    }

    if (sock->prog_id == curr_prog_id)
	bpf_set_link_xdp_fd(nethuns_socket(sock)->ifindex, -1, sock->xdp_flags);
    else if (!curr_prog_id)
        nethuns_perror(nethuns_socket(sock)->errbuf, "bpf_prog: could get find a prog id on interface '%d'", nethuns_socket(sock)->ifindex);
    else
        nethuns_perror(nethuns_socket(sock)->errbuf, "bpf_prog: program on interface '%d' changed.", nethuns_socket(sock)->ifindex);

    return 0;
}


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

    /* set defualt xdp_flags */

    sock->xdp_flags = 0; // or safer XDP_FLAGS_UPDATE_IF_NOEXIST;
    sock->xdp_bind_flags = XDP_USE_NEED_WAKEUP;

    switch(opt->mode)
    {
    case nethuns_cap_default: {
    	sock->xdp_flags |= XDP_FLAGS_SKB_MODE;
    	sock->xdp_bind_flags |= XDP_COPY;
    } break;
    case nethuns_cap_skb_mode: {
    	sock->xdp_flags |= XDP_FLAGS_SKB_MODE;
    	sock->xdp_bind_flags |= XDP_COPY;
    } break;
    case nethuns_cap_drv_mode: {
    	sock->xdp_flags |= XDP_FLAGS_DRV_MODE;
    	sock->xdp_bind_flags |= XDP_COPY;
    } break;
    case nethuns_cap_zero_copy: {
    	sock->xdp_flags |= XDP_FLAGS_DRV_MODE;
    	sock->xdp_bind_flags |= XDP_ZEROCOPY;
    }
    }

    nethuns_socket(sock)->ifindex = 0;

    nethuns_lock_global();

    if (!__nethuns_global.umem_refcnt++) {

        // TODO: support for HUGE pages
        // -> opt_umem_flags |= XDP_UMEM_UNALIGNED_CHUNK_FLAG;

        __nethuns_global.total_mem = opt->numblocks * opt->numpackets * opt->packetsize;

        __nethuns_global.bufs = mmap(NULL, __nethuns_global.total_mem,
                                     PROT_READ | PROT_WRITE,
                                     MAP_PRIVATE | MAP_ANONYMOUS /* | MAP_HUGETLB */, -1, 0);
        if (__nethuns_global.bufs == MAP_FAILED) {
            nethuns_perror(errbuf, "open: XDP bufs mmap failed");
            free(sock);
            return NULL;
	    }
        
	    __nethuns_global.umem = xsk_configure_umem(sock, __nethuns_global.bufs, __nethuns_global.total_mem, opt->packetsize);
        if (! __nethuns_global.umem) {
            nethuns_perror(errbuf, "open: XDP configure umem failed!");
            munmap(__nethuns_global.bufs, __nethuns_global.total_mem);
            free(sock);
            return NULL;
        }
    }

    nethuns_unlock_global();

    sock->base.opt = *opt;

    return sock;
}


int nethuns_close_xdp(struct nethuns_socket_xdp *s)
{
    if (s)
    {
	    // TODO: socket delete
	    // TODO: umem delete

	    unload_xdp_program(s);

        nethuns_lock_global();

        if (!--__nethuns_global.umem_refcnt) {
            xsk_umem__delete(__nethuns_global.umem->umem);
            munmap(__nethuns_global.bufs, __nethuns_global.total_mem);
        }

        nethuns_unlock_global();

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
    char errbuf[1024];

    if (queue != NETHUNS_ANY_QUEUE)
    {
        nethuns_perror(nethuns_socket(s)->errbuf, "open: only ANY_QUEUE is currently supported by this device");
        return -1;
    }

    nethuns_socket(s)->queue   = NETHUNS_ANY_QUEUE;
    nethuns_socket(s)->ifindex = (int)if_nametoindex(dev);

    if (load_xdp_program(s) < 0) {
	return -1;
    }


    nethuns_socket(s)->devname = strdup(dev);

    if (nethuns_socket(s)->opt.promisc)
    {
        if (__nethuns_set_if_promisc(s, dev) < 0)
            return -1;
    }

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

    // if (pcap_set_buffer_size(s->p, (int)(nethuns_socket(s)->opt.numblocks * nethuns_socket(s)->opt.numpackets * nethuns_socket(s)->opt.packetsize)) != 0)
    // {
    //     nethuns_perror(s->base.errbuf, "bind: %s", pcap_geterr(s->p));
    //     return -1;
    // }

    // if (nethuns_socket(s)->opt.promisc)
    // {
    //     if (pcap_set_promisc(s->p, 1) != 0)
    //     {
    //         nethuns_perror(s->base.errbuf, "bind: %s", pcap_geterr(s->p));
    //         return -1;
    //     }
    // }

    // if (pcap_set_snaplen(s->p, (int)nethuns_socket(s)->opt.packetsize) != 0)
    // {
    //     nethuns_perror(s->base.errbuf, "bind: %s", pcap_geterr(s->p));
    //     return -1;
    // }

    // if (pcap_set_timeout(s->p, (int)nethuns_socket(s)->opt.timeout_ms) != 0)
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

    // switch (nethuns_socket(s)->opt.dir)
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
    unsigned int caplen = nethuns_socket(s)->opt.packetsize;
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
    //     if (!nethuns_socket(s)->filter || nethuns_socket(s)->filter(nethuns_socket(s)->filter_ctx, &header, ppayload))
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


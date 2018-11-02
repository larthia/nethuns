#include "nethuns_base.h"
#include "devpcap.h"

#include <linux/version.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

struct nethuns_socket_devpcap *
nethuns_open_devpcap(struct nethuns_socket_options *opt, char *errbuf)
{
    struct nethuns_socket_devpcap *sock = malloc(sizeof(struct nethuns_socket_devpcap));
    memset(sock, 0, sizeof(*sock));

    /* set a single consumer by default */

    sock->base.sync.number = 1;
    sock->base.opt = *opt;
    return sock;
}


int nethuns_close_devpcap(struct nethuns_socket_devpcap *s)
{
    if (s)
    {
        free(s);
    }
    return 0;
}


int nethuns_bind_devpcap(struct nethuns_socket_devpcap *s, const char *dev)
{
    return 0;
}


int nethuns_fd_devpcap(struct nethuns_socket_devpcap *s)
{
    return 0;
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
nethuns_flush_devpcap(struct nethuns_socket_devpcap *s)
{
    return 0;
}


int
nethuns_send_devpcap(struct nethuns_socket_devpcap *s, uint8_t const *packet, unsigned int len)
{
    return 1;
}


int nethuns_set_consumer_devpcap(struct nethuns_socket_devpcap *s, unsigned int numb)
{
    if (numb >= sizeof(s->base.sync.id)/sizeof(s->base.sync.id[0]))
        return -1;
    s->base.sync.number = numb;
    return 0;
}


int
nethuns_fanout_devpcap(struct nethuns_socket_devpcap *s, int group, const char *fanout)
{
    return -1;
}


void
nethuns_dump_rings_devpcap(struct nethuns_socket_devpcap *s)
{
}


int
nethuns_get_stats_devpcap(struct nethuns_socket_devpcap *s, struct nethuns_stats *stats)
{
    return 0;
}

#include "internals/tpacketv3.h"
#include "nethuns.h"

#include <linux/version.h>
#include <sys/ioctl.h>
#include <poll.h>

nethuns_socket_t
nethuns_open(unsigned int numblocks, unsigned int numpackets, unsigned int packetsize)
{
    nethuns_socket_t sock;
    int fd, err, v = TPACKET_V3;
    unsigned int i;

    fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd == -1)
        return NULL;

    err = setsockopt(fd, SOL_PACKET, PACKET_VERSION, &v, sizeof(v));
    if (err < 0) {
        perror("nethuns: setsockopt PACKET_VERSION");
        return NULL;
    }

    sock = malloc(sizeof(struct tpacket_socket));
    memset(sock, 0, sizeof(*sock));

    sock->rx_ring.req.tp_block_size     = numpackets * packetsize;
    sock->rx_ring.req.tp_frame_size     = packetsize;
    sock->rx_ring.req.tp_block_nr       = numblocks;
    sock->rx_ring.req.tp_frame_nr       = numblocks * numpackets;
    sock->rx_ring.req.tp_retire_blk_tov = 60;
    sock->rx_ring.req.tp_feature_req_word = TP_FT_REQ_FILL_RXHASH;

    err = setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &sock->rx_ring.req, sizeof(sock->rx_ring.req));
    if (err < 0) {
        perror("nethuns: setsockopt RX_RING");
        free(sock);
        return NULL;
    }

    sock->rx_ring.map = mmap(NULL, sock->rx_ring.req.tp_block_size * sock->rx_ring.req.tp_block_nr, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED, fd, 0);
    if (sock->rx_ring.map == MAP_FAILED) {
        perror("nethuns: mmap");
        free(sock);
        return NULL;
    }

    sock->rx_ring.rd = malloc(sock->rx_ring.req.tp_block_nr * sizeof(*(sock->rx_ring.rd)));

	for (i = 0; i < sock->rx_ring.req.tp_block_nr; ++i) {
		sock->rx_ring.rd[i].iov_base = sock->rx_ring.map + (i * sock->rx_ring.req.tp_block_size);
		sock->rx_ring.rd[i].iov_len  = sock->rx_ring.req.tp_block_size;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)

    sock->tx_ring.req.tp_block_size     = numpackets * packetsize;
    sock->tx_ring.req.tp_frame_size     = packetsize;
    sock->tx_ring.req.tp_block_nr       = numblocks;
    sock->tx_ring.req.tp_frame_nr       = numblocks * numpackets;

    err = setsockopt(fd, SOL_PACKET, PACKET_TX_RING, &sock->tx_ring.req, sizeof(sock->tx_ring.req));
    if (err < 0) {
        perror("nethuns: setsockopt TX_RING");
	    munmap(sock->rx_ring.map, sock->rx_ring.req.tp_block_size * sock->rx_ring.req.tp_block_nr);
	    close(fd);
        free(sock);
        return NULL;
    }

    sock->tx_ring.map = mmap(NULL, sock->tx_ring.req.tp_block_size * sock->tx_ring.req.tp_block_nr, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED, fd, 0);
    if (sock->tx_ring.map == MAP_FAILED) {
        perror("nethuns: mmap");
	    munmap(sock->rx_ring.map, sock->rx_ring.req.tp_block_size * sock->rx_ring.req.tp_block_nr);
	    close(fd);
        free(sock);
        return NULL;
    }

#endif

    sock->fd = fd;
    sock->rx_block_idx = 0;
    sock->tx_block_idx = 0;
    sock->rx_frame_idx = 0;
    sock->tx_frame_idx = 0;

	sock->pfd.fd = fd;
	sock->pfd.events = POLLIN | POLLERR;
	sock->pfd.revents = 0;

    /* set a single consumer by default */

    sock->sync.number = 1;

    return sock;
}


int nethuns_bind(nethuns_socket_t s, const char *dev)
{
    struct sockaddr_ll addr;
    int err;

    memset(&addr, 0, sizeof(addr));

    addr.sll_family   = AF_PACKET;
    addr.sll_protocol = ntohs(ETH_P_ALL);
    addr.sll_ifindex  = (int)if_nametoindex(dev);

    if (!addr.sll_ifindex) {
        perror("nethuns: if_nametoindex");
        return -1;
    }

    err = bind(s->fd, (struct sockaddr *)&addr, sizeof(addr));
    if (err < 0) {
        perror("nethuns: bind");
        return -1;
    }

    return 0;
}


int nethuns_fd(nethuns_socket_t s)
{
    return s->fd;
}


int nethuns_close(nethuns_socket_t s)
{
    if (s)
    {
	    munmap(s->rx_ring.map, s->rx_ring.req.tp_block_size * s->rx_ring.req.tp_block_nr);
	    munmap(s->rx_ring.map, s->rx_ring.req.tp_block_size * s->rx_ring.req.tp_block_nr);
        close(s->fd);
        free(s);
    }
    return 0;
}


uint64_t
nethuns_recv(nethuns_socket_t s, nethuns_pkthdr_t **pkthdr, uint8_t **pkt)
{
    nethuns_block_t * pb = __nethuns_block(s, s->rx_block_idx);

    if (unlikely((pb->hdr.block_status & TP_STATUS_USER) == 0))
    {
        nethuns_flush(s);
        poll(&s->pfd, 1, -1);
        return 0;
    }

    if (s->rx_frame_idx < pb->hdr.num_pkts)
    {
        if (s->rx_frame_idx++ == 0)
        {
            s->ppd = (struct tpacket3_hdr *) ((uint8_t *) pb + pb->hdr.offset_to_first_pkt);
        }

        *pkthdr = s->ppd;
        *pkt    = (uint8_t *)(s->ppd) + s->ppd->tp_mac;
        return s->rx_block_idx;
    }

    nethuns_flush(s);

    if ((s->rx_block_idx - s-> rx_block_idx_rls) < (s->rx_ring.req.tp_block_nr - 1))
    {
        s->rx_block_idx++;
        s->rx_frame_idx = 0;
    }
    return 0;
}

int
nethuns_flush(nethuns_socket_t s)
{
    uint64_t rid = s->rx_block_idx_rls, cur = UINT64_MAX;
    unsigned int i;

    for(i = 0; i < s->sync.number; i++)
        cur = MIN(cur, __atomic_load_n(&s->sync.id[i].value, __ATOMIC_RELAXED));

    for(; rid < cur; ++rid)
    {
        nethuns_block_t *pb = __nethuns_block(s, rid);
        pb->hdr.block_status = TP_STATUS_KERNEL;
    }

    s->rx_block_idx_rls = rid;
    return 0;
}


int nethuns_set_consumer(nethuns_socket_t s, unsigned int numb)
{
    if (numb >= sizeof(s->sync.id)/sizeof(s->sync.id[0]))
        return -1;
    s->sync.number = numb;
    return 0;
}



#include "tpacket_v3.h"

#include <linux/version.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <errno.h>


nethuns_socket_t
nethuns_open_tpacket_v3(unsigned int numblocks, unsigned int numpackets, unsigned int packetsize)
{
    nethuns_socket_t sock;
    int fd, err, v = TPACKET_V3;
    unsigned int i;

    fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd == -1)
        return NULL;

    err = setsockopt(fd, SOL_PACKET, PACKET_VERSION, &v, sizeof(v));
    if (err < 0) {
        perror("nethuns: setsockopt PACKET_VERSION v3");
        close(fd);
        return NULL;
    }

    sock = malloc(sizeof(struct tpacket_v3_socket));
    memset(sock, 0, sizeof(*sock));

    sock->rx_ring.req.tp_block_size     = numpackets * packetsize;
    sock->rx_ring.req.tp_frame_size     = packetsize;
    sock->rx_ring.req.tp_block_nr       = numblocks;
    sock->rx_ring.req.tp_frame_nr       = numblocks * numpackets;
    sock->rx_ring.req.tp_retire_blk_tov = 60;
    sock->rx_ring.req.tp_sizeof_priv    = 0;
    sock->rx_ring.req.tp_feature_req_word = TP_FT_REQ_FILL_RXHASH;

    err = setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &sock->rx_ring.req, sizeof(sock->rx_ring.req));
    if (err < 0) {
        perror("nethuns: setsockopt RX_RING");
        free(sock);
        close(fd);
        return NULL;
    }

    sock->tx_ring.req.tp_block_size     = numpackets * packetsize;
    sock->tx_ring.req.tp_frame_size     = packetsize;
    sock->tx_ring.req.tp_block_nr       = numblocks;
    sock->tx_ring.req.tp_frame_nr       = numblocks * numpackets;

    err = setsockopt(fd, SOL_PACKET, PACKET_TX_RING, &sock->tx_ring.req, sizeof(sock->tx_ring.req));
    if (err < 0) {
        perror("nethuns: setsockopt TX_RING");
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
        perror("nethuns: mmap");
        free(sock);
        close(fd);
        return NULL;
    }

    sock->tx_ring.map = sock->rx_ring.map + (sock->rx_ring.req.tp_block_size * sock->rx_ring.req.tp_block_nr);

    /* setup Rx ring... */

    sock->rx_ring.rd = malloc(sock->rx_ring.req.tp_block_nr * sizeof(*(sock->rx_ring.rd)));
    memset(sock->rx_ring.rd, 0, sock->rx_ring.req.tp_block_nr * sizeof(*(sock->rx_ring.rd)));

	for (i = 0; i < sock->rx_ring.req.tp_block_nr; ++i) {
		sock->rx_ring.rd[i].iov_base = sock->rx_ring.map + (i * sock->rx_ring.req.tp_block_size);
		sock->rx_ring.rd[i].iov_len  = sock->rx_ring.req.tp_block_size;
	}

    /* setup Tx ring... */

    sock->tx_ring.rd = malloc(sock->tx_ring.req.tp_block_nr * sizeof(*(sock->tx_ring.rd)));
    memset(sock->tx_ring.rd, 0, sock->tx_ring.req.tp_block_nr * sizeof(*(sock->tx_ring.rd)));

	for (i = 0; i < sock->tx_ring.req.tp_block_nr; ++i) {
		sock->tx_ring.rd[i].iov_base = sock->tx_ring.map + (i * sock->tx_ring.req.tp_block_size);
		sock->tx_ring.rd[i].iov_len  = sock->tx_ring.req.tp_block_size;
	}

    /* QDISC bypass */

    int one = 1;
    setsockopt(fd, SOL_PACKET, PACKET_QDISC_BYPASS, &one, sizeof(one));


    sock->fd = fd;
    sock->rx_block_idx = 0;
    sock->tx_block_idx = 0;
    sock->rx_frame_idx = 0;
    sock->tx_frame_idx = 0;


    sock->rx_pfd.fd = fd;
    sock->rx_pfd.events = POLLIN | POLLERR;
    sock->rx_pfd.revents = 0;


    sock->tx_pfd.fd = fd;
    sock->tx_pfd.events = POLLOUT | POLLERR;
    sock->tx_pfd.revents = 0;

    /* set a single consumer by default */

    sock->sync.number = 1;

    return sock;
}


int nethuns_close_tpacket_v3(nethuns_socket_t s)
{
    if (s)
    {
	    free(s->tx_ring.rd);
	    free(s->rx_ring.rd);
	    munmap(s->rx_ring.map, s->rx_ring.req.tp_block_size * s->rx_ring.req.tp_block_nr +
	                           s->tx_ring.req.tp_block_size * s->tx_ring.req.tp_block_nr);
        close(s->fd);
        free(s);
    }
    return 0;
}


int nethuns_bind_tpacket_v3(nethuns_socket_t s, const char *dev)
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


int nethuns_fd_tpacket_v3(nethuns_socket_t s)
{
    return s->fd;
}



int
__nethuns_blocks_release_tpacket_v3(nethuns_socket_t s)
{
    uint64_t rid = s->rx_block_idx_rls, cur = UINT64_MAX;
    unsigned int i;

    for(i = 0; i < s->sync.number; i++)
        cur = MIN(cur, __atomic_load_n(&s->sync.id[i].value, __ATOMIC_RELAXED));

    for(; rid < cur; ++rid)
    {
        nethuns_block_t *pb = __nethuns_block_rx_tpacket_v3(s, rid);
        pb->hdr.block_status = TP_STATUS_KERNEL;
    }

    s->rx_block_idx_rls = rid;
    return 0;
}


uint64_t
nethuns_recv_tpacket_v3(nethuns_socket_t s, nethuns_pkthdr_t **pkthdr, uint8_t **pkt)
{
    nethuns_block_t * pb;

    pb = __nethuns_block_rx_tpacket_v3(s, s->rx_block_idx);

    if (unlikely((pb->hdr.block_status & TP_STATUS_USER) == 0))
    {
        __nethuns_blocks_release_tpacket_v3(s);
        poll(&s->rx_pfd, 1, -1);
        return 0;
    }

    if (s->rx_frame_idx < pb->hdr.num_pkts)
    {
        if (unlikely(s->rx_frame_idx++ == 0))
        {
            s->rx_ppd = (struct tpacket3_hdr *) ((uint8_t *) pb + pb->hdr.offset_to_first_pkt);
        }

        *pkthdr    = s->rx_ppd;
        *pkt       = (uint8_t *)(s->rx_ppd) + s->rx_ppd->tp_mac;
		s->rx_ppd  = (struct tpacket3_hdr *) ((uint8_t *) s->rx_ppd + s->rx_ppd->tp_next_offset);

        return s->rx_block_idx;
    }

    __nethuns_blocks_release_tpacket_v3(s);

    if ((s->rx_block_idx - s-> rx_block_idx_rls) < (s->rx_ring.req.tp_block_nr - 1))
    {
        s->rx_block_idx++;
        s->rx_frame_idx = 0;
    }

    return 0;
}


int
nethuns_flush_tpacket_v3(nethuns_socket_t s)
{
    if (sendto(s->fd, NULL, 0, 0, NULL, 0) < 0) {
        perror("nethuns: flush");
        return -1;
    }

    return 0;
}


int
nethuns_send_tpacket_v3(nethuns_socket_t s, uint8_t *packet, unsigned int len)
{
    const size_t numpackets = s->tx_ring.req.tp_block_size/s->tx_ring.req.tp_frame_size;

    uint8_t *pbase;

    if (s->tx_frame_idx == numpackets)
    {
        int ret = nethuns_flush_tpacket_v3(s);
        if (ret == -1) {
            perror("nethuns: flush");
            return -1;
        }

        s->tx_block_idx++;
        s->tx_frame_idx = 0;
    }

    pbase = (uint8_t *)__nethuns_block_tx_tpacket_v3(s, s->tx_block_idx);

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
    return 1;
}


int nethuns_set_consumer_tpacket_v3(nethuns_socket_t s, unsigned int numb)
{
    if (numb >= sizeof(s->sync.id)/sizeof(s->sync.id[0]))
        return -1;
    s->sync.number = numb;
    return 0;
}



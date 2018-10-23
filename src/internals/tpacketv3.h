# pragma once

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <unistd.h>
#include <signal.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

#include "synapse.h"


struct ring_v3
{
    struct iovec *rd;
    uint8_t *map;
    struct tpacket_req3 req;
};


struct tpacket_socket
{
    int fd;

    struct ring_v3  rx_ring;
    struct ring_v3  tx_ring;

    uint64_t        rx_block_idx;
    uint64_t        rx_block_idx_rls;

    uint64_t        tx_block_idx;
    uint64_t        tx_block_idx_rsl;

    unsigned int    rx_frame_idx;
    unsigned int    tx_frame_idx;

    struct pollfd   pfd;

    struct tpacket3_hdr *ppd;

    struct nethuns_synapse sync;
};


struct block_desc
{
	uint32_t version;
	uint32_t offset_to_priv;
	struct tpacket_hdr_v1 hdr;
};

typedef struct tpacket_socket *  nethuns_socket_t;

typedef struct block_desc        nethuns_block_t;
typedef struct tpacket3_hdr      nethuns_pkthdr_t;


#ifdef __cplusplus
extern "C" {
#endif


static inline
nethuns_block_t *
__nethuns_block(nethuns_socket_t s, uint64_t id)
{
    return (nethuns_block_t *) s->rx_ring.rd[id % s->rx_ring.req.tp_block_nr].iov_base;
}


static inline int
nethuns_release(nethuns_socket_t s, nethuns_pkthdr_t *pkt, uint64_t block_id, unsigned int consumer)
{
    __atomic_store_n(&s->sync.id[consumer].value, block_id, __ATOMIC_RELAXED);
    (void)pkt;
    return 0;
}


#ifdef __cplusplus
}
#endif


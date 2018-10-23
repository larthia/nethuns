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
    struct nethuns_synapse sync;
};


struct tpacket_socket
{
    int fd;

    struct ring_v3  rx_ring;
    struct ring_v3  tx_ring;

    uint64_t        rx_block_idx;
    uint64_t        tx_block_idx;

    int             rx_frame_idx;
    int             tx_frame_idx;

    struct pollfd   pfd;
};


struct block_desc
{
	uint32_t version;
	uint32_t offset_to_priv;
	struct tpacket_hdr_v1 hdr;
};


typedef struct block_desc     *  nethuns_block_t;
typedef struct tpacket3_hdr   *  nethuns_pkthdr_t;
typedef struct tpacket_socket *  nethuns_socket_t;

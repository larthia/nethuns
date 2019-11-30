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

#include "../types.h"


struct ring_v3
{
    struct iovec *rd;
    uint8_t *map;
    struct tpacket_req3 req;
};


struct nethuns_socket_tpacket_v3
{
    struct nethuns_socket_data base;

    struct ring_v3  rx_ring;
    struct ring_v3  tx_ring;

    uint64_t        rx_block_mod;
    uint64_t        rx_block_idx;
    uint64_t        rx_block_idx_rls;

    uint64_t        tx_block_mod;
    uint64_t        tx_block_idx;
    uint64_t        tx_block_idx_rls;

    unsigned int    rx_frame_idx;
    unsigned int    tx_frame_idx;

    int             fd;

    struct pollfd   rx_pfd;
    struct pollfd   tx_pfd;

    struct tpacket3_hdr *rx_ppd;
    struct tpacket3_hdr *tx_ppd;
};


struct block_descr_v3
{
    uint32_t version;
    uint32_t offset_to_priv;
    struct tpacket_hdr_v1 hdr;
};


#ifdef __cplusplus
extern "C" {
#endif


static inline
struct block_descr_v3 *
__nethuns_block_mod_tpacket_v3(struct ring_v3 *ring, uint64_t id)
{
    return (struct block_descr_v3 *) ring->rd[id % ring->req.tp_block_nr].iov_base;
}

static inline
struct block_descr_v3 *
__nethuns_block_tpacket_v3(struct ring_v3 *ring, uint64_t id_mod)
{
    return (struct block_descr_v3 *) ring->rd[id_mod].iov_base;
}


static inline uint32_t
nethuns_tstamp_sec_tpacket_v3(struct tpacket3_hdr const *hdr)
{
    return hdr->tp_sec;
}

static inline uint32_t
nethuns_tstamp_usec_tpacket_v3(struct tpacket3_hdr const *hdr)
{
    return hdr->tp_nsec/1000;
}

static inline uint32_t
nethuns_tstamp_nsec_tpacket_v3(struct tpacket3_hdr const *hdr)
{
    return hdr->tp_nsec;
}

static inline
void nethuns_tstamp_set_sec_tpacket_v3(struct tpacket3_hdr *hdr, uint32_t v) {
    hdr->tp_sec = v;
}

static inline
void nethuns_tstamp_set_usec_tpacket_v3(struct tpacket3_hdr *hdr, uint32_t v) {
    hdr->tp_nsec = v *1000;
}

static inline
void nethuns_tstamp_set_nsec_tpacket_v3(struct tpacket3_hdr *hdr, uint32_t v)  {
    hdr->tp_nsec = v;
}

static inline uint32_t
nethuns_snaplen_tpacket_v3(struct tpacket3_hdr const *hdr) {
    return hdr->tp_snaplen;
}

static inline uint32_t
nethuns_len_tpacket_v3(struct tpacket3_hdr const *hdr) {
    return hdr->tp_len;
}

static inline void
nethuns_set_snaplen_tpacket_v3(struct tpacket3_hdr *hdr, uint32_t v) {
    hdr->tp_snaplen = v;
}

static inline void
nethuns_set_len_tpacket_v3(struct tpacket3_hdr *hdr, uint32_t v) {
    hdr->tp_len = v;
}

static inline uint32_t
nethuns_rxhash_tpacket_v3(struct tpacket3_hdr const *hdr) {
    return hdr->hv1.tp_rxhash;
}

static inline uint16_t
nethuns_offvlan_tci_tpacket_v3(struct tpacket3_hdr const *hdr) {
    return hdr->hv1.tp_vlan_tci;
}

static inline uint16_t
nethuns_offvlan_tpid_tpacket_v3(struct tpacket3_hdr const *hdr) {
    return hdr->hv1.tp_vlan_tpid;
}


#ifdef __cplusplus
}
#endif


// Copyright 2021 Larthia, University of Pisa. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

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

#include <linux/types.h>

//
// Workaround: if __LINUX_TYPES_H is defined, then we are compiling against the broken linux/types.h of libbpf.
// To fix it, we need to add the following typedefs before including <linux/ip.h> 
// https://patchwork.ozlabs.org/project/netdev/patch/20190518004639.20648-2-mcroce@redhat.com/

#ifdef __LINUX_TYPES_H
typedef __u16 __bitwise __sum16;
typedef __u32 __bitwise __wsum;
#endif
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
    struct nethuns_socket_base base;

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



nethuns_pcap_t *
nethuns_pcap_open_tpacket_v3(struct nethuns_socket_options *opt, const char *filename, int mode, char *errbuf);

int 
nethuns_pcap_close_tpacket_v3(nethuns_pcap_t *p);

uint64_t
nethuns_pcap_read_tpacket_v3(nethuns_pcap_t *p, nethuns_pkthdr_t const **pkthdr, uint8_t const **payload); 

int
nethuns_pcap_write_tpacket_v3(nethuns_pcap_t *s, struct nethuns_pcap_pkthdr const *header, uint8_t const *packet, unsigned int len);

int
nethuns_pcap_store_tpacket_v3(nethuns_pcap_t *s, nethuns_pkthdr_t const *pkthdr, uint8_t const *packet, unsigned int len);

int 
nethuns_pcap_rewind_tpacket_v3(nethuns_pcap_t *s);


struct nethuns_socket_tpacket_v3 *
nethuns_open_tpacket_v3(struct nethuns_socket_options *opt, char *errbuf);

int
nethuns_close_tpacket_v3(struct nethuns_socket_tpacket_v3 *s);

int
nethuns_bind_tpacket_v3(struct nethuns_socket_tpacket_v3 *s, const char *dev, int queue);

uint64_t
nethuns_recv_tpacket_v3(struct nethuns_socket_tpacket_v3 *s, nethuns_pkthdr_t const **pkthdr, uint8_t const **payload);

int
nethuns_send_tpacket_v3(struct nethuns_socket_tpacket_v3 *s, uint8_t const *packet, unsigned int len);

static inline uint8_t *
nethuns_get_buf_addr_tpacket_v3(__maybe_unused nethuns_socket_t * s, __maybe_unused uint64_t pktid) {
    return NULL;
}

int
nethuns_flush_tpacket_v3(__maybe_unused struct nethuns_socket_tpacket_v3 *s);

int
nethuns_stats_tpacket_v3(struct nethuns_socket_tpacket_v3 *s, struct nethuns_stat *stats);

int
nethuns_fanout_tpacket_v3(__maybe_unused struct nethuns_socket_tpacket_v3 *s, __maybe_unused int group, __maybe_unused const char *fanout);

int
nethuns_fd_tpacket_v3(__maybe_unused struct nethuns_socket_tpacket_v3 *s);

void
nethuns_dump_rings_tpacket_v3(__maybe_unused struct nethuns_socket_tpacket_v3 *s);

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


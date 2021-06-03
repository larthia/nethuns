# pragma once

#include <stdio.h>

#include "../misc/compiler.h"
#include "../misc/macro.h"
#include "../vlan.h"
#include "../types.h"

#include "xdp_pkthdr.h"
#include "xsk_ext.h"

#include "base.h"

struct nethuns_socket_xdp
{
    struct nethuns_socket_base base;

    uint32_t xdp_flags;
    uint32_t xdp_bind_flags;

    struct bpf_object *obj;

    struct xsk_socket_info *xsk;

    struct xsk_umem_info *umem;
    void *bufs;
    size_t total_mem;
    uint64_t first_tx_frame;
    uint64_t num_tx_frames;
    uint64_t first_rx_frame;
    uint64_t num_rx_frames;
    size_t framesz; /* real size of each frame (power of 2) */
    size_t fshift; /* log_2 of the frame size */

    bool rx;
    bool tx;

    unsigned int rcvd;
    unsigned int toflush;
    uint32_t idx_rx;
};


#ifdef __cplusplus
extern "C" {
#endif

nethuns_pcap_t *
nethuns_pcap_open_xdp(struct nethuns_socket_options *opt, const char *filename, int mode, char *errbuf);

int 
nethuns_pcap_close_xdp(nethuns_pcap_t *p);

uint64_t
nethuns_pcap_read_xdp(nethuns_pcap_t *p, nethuns_pkthdr_t const **pkthdr, uint8_t const **payload); 

int
nethuns_pcap_write_xdp(nethuns_pcap_t *s, struct nethuns_pcap_pkthdr const *header, uint8_t const *packet, unsigned int len);

int
nethuns_pcap_store_xdp(nethuns_pcap_t *s, nethuns_pkthdr_t const *pkthdr, uint8_t const *packet, unsigned int len);

int 
nethuns_pcap_rewind_xdp(nethuns_pcap_t *s);

struct nethuns_socket_xdp *
nethuns_open_xdp(struct nethuns_socket_options *opt, char *errbuf);

int 
nethuns_close_xdp(struct nethuns_socket_xdp *s);

int 
nethuns_bind_xdp(struct nethuns_socket_xdp *s, const char *dev, int queue);

uint64_t
nethuns_recv_xdp(struct nethuns_socket_xdp *s, nethuns_pkthdr_t const **pkthdr, uint8_t const **payload);

int
nethuns_send_xdp(struct nethuns_socket_xdp *s, uint8_t const *packet, unsigned int len);

int
nethuns_flush_xdp(__maybe_unused struct nethuns_socket_xdp *s);

int
nethuns_stats_xdp(struct nethuns_socket_xdp *s, struct nethuns_stat *stats);

int nethuns_fd_xdp(__maybe_unused struct nethuns_socket_xdp *s);

int
nethuns_fanout_xdp(__maybe_unused struct nethuns_socket_xdp *s, __maybe_unused int group, __maybe_unused const char *fanout);

void
nethuns_dump_rings_xdp(__maybe_unused struct nethuns_socket_xdp *s);

static inline uint32_t
nethuns_tstamp_sec_xdp(struct xdp_pkthdr const *hdr) {
    return (uint32_t)hdr->sec;
}
static inline uint32_t
nethuns_tstamp_usec_xdp(struct xdp_pkthdr const *hdr) {
    return (uint32_t)hdr->nsec/1000;
}

static inline uint32_t
nethuns_tstamp_nsec_xdp(struct xdp_pkthdr const *hdr) {
    return (uint32_t)hdr->nsec;
}

static inline
void nethuns_tstamp_set_sec_xdp(struct xdp_pkthdr *hdr, uint32_t v) {
    hdr->sec = v;
}

static inline
void nethuns_tstamp_set_usec_xdp(struct xdp_pkthdr *hdr, uint32_t v) {
    hdr->nsec = v * 1000;
}

static inline
void nethuns_tstamp_set_nsec_xdp(struct xdp_pkthdr *hdr, uint32_t v) {
    hdr->nsec = v;
}

static inline uint32_t
nethuns_snaplen_xdp(struct xdp_pkthdr const *hdr) {
    return hdr->snaplen;
}

static inline uint32_t
nethuns_len_xdp(struct xdp_pkthdr const *hdr) {
    return hdr->len;
}

static inline void
nethuns_set_snaplen_xdp(struct xdp_pkthdr *hdr, uint32_t v) {
    hdr->snaplen = v;
}

static inline void
nethuns_set_len_xdp(struct xdp_pkthdr *hdr, uint32_t v) {
    hdr->len = v;
}

static inline uint32_t
nethuns_rxhash_xdp(__maybe_unused struct xdp_pkthdr const *hdr)  {
    return 0;
}

static inline uint16_t
nethuns_offvlan_tpid_xdp(__maybe_unused struct xdp_pkthdr const *hdr) {
    return 0;
}

static inline uint16_t
nethuns_offvlan_tci_xdp(__maybe_unused struct xdp_pkthdr const *hdr) {
    return 0;
}

static inline uint64_t
tx_frame(struct nethuns_socket_xdp *s, uint64_t idx)
{
		return (s->first_tx_frame + (idx & s->base.tx_ring.mask)) << s->fshift;
}

static inline uint64_t
tx_slot(struct nethuns_socket_xdp *s, uint64_t frame)
{
		return ((frame >> s->fshift) - s->first_tx_frame) & s->base.tx_ring.mask;
}

static inline uint64_t
rx_frame(struct nethuns_socket_xdp *s, uint64_t idx)
{
		return (s->first_rx_frame + (idx & s->base.rx_ring.mask)) << s->fshift;
}

#ifdef __cplusplus
}
#endif


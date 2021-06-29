# pragma once

#include <stdio.h>

#include "../types.h"
#include "../misc/compiler.h"

#include "xdp_pkthdr.h"
#include "xdp/xsk_ext.h"

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

    bool rx;
    bool tx;
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

#ifdef __cplusplus
}
#endif


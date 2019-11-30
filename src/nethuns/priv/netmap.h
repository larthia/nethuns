# pragma once

#include <stdio.h>

#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>

#include "../types.h"


struct nethuns_socket_netmap
{
    struct nethuns_socket_data base;
    struct nm_desc *p;
};

#ifdef __cplusplus
extern "C" {
#endif


static inline uint32_t
nethuns_tstamp_sec_netmap(struct nm_pkthdr const *hdr) {
    return (uint32_t)hdr->ts.tv_sec;
}

static inline uint32_t
nethuns_tstamp_usec_netmap(struct nm_pkthdr const *hdr) {
    return (uint32_t)hdr->ts.tv_usec;
}

static inline uint32_t
nethuns_tstamp_nsec_netmap(struct nm_pkthdr const *hdr) {
    return (uint32_t)hdr->ts.tv_usec * 1000;
}

static inline
void nethuns_tstamp_set_sec_netmap(struct nm_pkthdr *hdr, uint32_t v) {
    hdr->ts.tv_sec = v;
}

static inline
void nethuns_tstamp_set_usec_netmap(struct nm_pkthdr *hdr, uint32_t v) {
    hdr->ts.tv_usec = v;
}

static inline
void nethuns_tstamp_set_nsec_netmap(struct nm_pkthdr *hdr, uint32_t v) {
    hdr->ts.tv_usec = v/1000;
}

static inline uint32_t
nethuns_snaplen_netmap(struct nm_pkthdr const *hdr) {
    return hdr->caplen;
}

static inline uint32_t
nethuns_len_netmap(struct nm_pkthdr const *hdr) {
    return hdr->len;
}

static inline void
nethuns_set_snaplen_netmap(struct nm_pkthdr *hdr, uint32_t v) {
    hdr->caplen = v;
}

static inline void
nethuns_set_len_netmap(struct nm_pkthdr *hdr, uint32_t v) {
    hdr->len = v;
}

static inline uint32_t
nethuns_rxhash_netmap(struct nm_pkthdr const *hdr) {
    return 0;
}

static inline uint16_t
nethuns_offvlan_tpid_netmap(struct nm_pkthdr const *hdr) {
    return 0;
}

static inline uint16_t
nethuns_offvlan_tci_netmap(struct nm_pkthdr const *hdr) {
    return 0;
}


#ifdef __cplusplus
}
#endif


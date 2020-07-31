# pragma once

#include <stdio.h>
#include <pcap/pcap.h>

#include "../types.h"
#include "../util/compiler.h"
#include "../util/macro.h"

struct nethuns_socket_libpcap
{
    struct nethuns_socket_base base;
    pcap_t  *p;
};

#ifdef __cplusplus
extern "C" {
#endif

static inline uint32_t
nethuns_tstamp_sec_libpcap(struct pcap_pkthdr const *hdr) {
    return (uint32_t)hdr->ts.tv_sec;
}
static inline uint32_t
nethuns_tstamp_usec_libpcap(struct pcap_pkthdr const *hdr) {
    return (uint32_t)hdr->ts.tv_usec;
}

static inline uint32_t
nethuns_tstamp_nsec_libpcap(struct pcap_pkthdr const *hdr) {
    return (uint32_t)hdr->ts.tv_usec * 1000;
}

static inline
void nethuns_tstamp_set_sec_libpcap(struct pcap_pkthdr *hdr, uint32_t v) {
    hdr->ts.tv_sec = v;
}

static inline
void nethuns_tstamp_set_usec_libpcap(struct pcap_pkthdr *hdr, uint32_t v) {
    hdr->ts.tv_usec = v;
}

static inline
void nethuns_tstamp_set_nsec_libpcap(struct pcap_pkthdr *hdr, uint32_t v) {
    hdr->ts.tv_usec = v/1000;
}

static inline uint32_t
nethuns_snaplen_libpcap(struct pcap_pkthdr const *hdr) {
    return hdr->caplen;
}

static inline uint32_t
nethuns_len_libpcap(struct pcap_pkthdr const *hdr) {
    return hdr->len;
}

static inline void
nethuns_set_snaplen_libpcap(struct pcap_pkthdr *hdr, uint32_t v) {
    hdr->caplen = v;
}

static inline void
nethuns_set_len_libpcap(struct pcap_pkthdr *hdr, uint32_t v) {
    hdr->len = v;
}

static inline uint32_t
nethuns_rxhash_libpcap(__maybe_unused struct pcap_pkthdr const *hdr)  {
    return 0;
}

static inline uint16_t
nethuns_offvlan_tpid_libpcap(__maybe_unused struct pcap_pkthdr const *hdr) {
    return 0;
}

static inline uint16_t
nethuns_offvlan_tci_libpcap(__maybe_unused struct pcap_pkthdr const *hdr) {
    return 0;
}


#ifdef __cplusplus
}
#endif

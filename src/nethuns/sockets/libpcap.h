# pragma once

#include <stdio.h>
#include <pcap/pcap.h>

#include "../misc/compiler.h"
#include "../misc/macro.h"
#include "../vlan.h"
#include "../types.h"

struct nethuns_socket_libpcap
{
    struct nethuns_socket_base base;
    pcap_t  *p;
};

#ifdef __cplusplus
extern "C" {
#endif


nethuns_pcap_t *
nethuns_pcap_open_libpcap(struct nethuns_socket_options *opt, const char *filename, int mode, char *errbuf);

int 
nethuns_pcap_close_libpcap(nethuns_pcap_t *p);

uint64_t
nethuns_pcap_read_libpcap(nethuns_pcap_t *p, nethuns_pkthdr_t const **pkthdr, uint8_t const **payload); 

int
nethuns_pcap_write_libpcap(nethuns_pcap_t *s, struct nethuns_pcap_pkthdr const *header, uint8_t const *packet, unsigned int len);

int
nethuns_pcap_store_libpcap(nethuns_pcap_t *s, nethuns_pkthdr_t const *pkthdr, uint8_t const *packet, unsigned int len);

int 
nethuns_pcap_rewind_libpcap(nethuns_pcap_t *s);


struct nethuns_socket_libpcap *
nethuns_open_libpcap(struct nethuns_socket_options *opt, char *errbuf);

int
nethuns_close_libpcap(struct nethuns_socket_libpcap *s);

int
nethuns_bind_libpcap(struct nethuns_socket_libpcap *s, const char *dev, int queue);

uint64_t
nethuns_recv_libpcap(struct nethuns_socket_libpcap *s, nethuns_pkthdr_t const **pkthdr, uint8_t const **payload);

int
nethuns_send_libpcap(struct nethuns_socket_libpcap *s, uint8_t const *packet, unsigned int len);

static inline uint8_t *
nethuns_get_buf_addr_libpcap(__maybe_unused nethuns_socket_t * s, __maybe_unused uint64_t pktid) {
    return NULL;
}

int
nethuns_flush_libpcap(__maybe_unused struct nethuns_socket_libpcap *s);

int
nethuns_stats_libpcap(struct nethuns_socket_libpcap *s, struct nethuns_stat *stats);

int
nethuns_fanout_libpcap(__maybe_unused struct nethuns_socket_libpcap *s, __maybe_unused int group, __maybe_unused const char *fanout);

int
nethuns_fd_libpcap(__maybe_unused struct nethuns_socket_libpcap *s);

void
nethuns_dump_rings_libpcap(__maybe_unused struct nethuns_socket_libpcap *s);


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

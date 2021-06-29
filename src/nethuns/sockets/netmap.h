# pragma once

#include <stdio.h>

#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>

#include "../types.h"


struct nethuns_socket_netmap
{
    struct nethuns_socket_base base;
    struct nm_desc *p;
};

#ifdef __cplusplus
extern "C" {
#endif


nethuns_pcap_t *
nethuns_pcap_open_netmap(struct nethuns_socket_options *opt, const char *filename, int mode, char *errbuf);

int 
nethuns_pcap_close_netmap(nethuns_pcap_t *p);

uint64_t
nethuns_pcap_read_netmap(nethuns_pcap_t *p, nethuns_pkthdr_t const **pkthdr, uint8_t const **payload); 

int
nethuns_pcap_write_netmap(nethuns_pcap_t *s, struct nethuns_pcap_pkthdr const *header, uint8_t const *packet, unsigned int len);

int
nethuns_pcap_store_netmap(nethuns_pcap_t *s, nethuns_pkthdr_t const *pkthdr, uint8_t const *packet, unsigned int len);

int 
nethuns_pcap_rewind_netmap(nethuns_pcap_t *s);



struct nethuns_socket_netmap * 
nethuns_open_netmap(struct nethuns_socket_options *opt, char *errbuf);

int nethuns_close_netmap(struct nethuns_socket_netmap *s);

int nethuns_bind_netmap(struct nethuns_socket_netmap *s, const char *dev, int queue);

uint64_t
nethuns_recv_netmap(struct nethuns_socket_netmap *s, nethuns_pkthdr_t const **pkthdr, uint8_t const **payload);

int
nethuns_send_netmap(struct nethuns_socket_netmap *s, uint8_t const *packet, unsigned int len);

int
nethuns_flush_netmap(struct nethuns_socket_netmap *s);

int
nethuns_stats_netmap(struct nethuns_socket_netmap *s, struct nethuns_stat *stats);

int
nethuns_fanout_netmap(__maybe_unused struct nethuns_socket_netmap *s, __maybe_unused int group, __maybe_unused const char *fanout);


int nethuns_fd_netmap(__maybe_unused struct nethuns_socket_netmap *s);

void
nethuns_dump_rings_netmap(__maybe_unused struct nethuns_socket_netmap *s);

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
nethuns_rxhash_netmap(__maybe_unused struct nm_pkthdr const *hdr) {
    return 0;
}

static inline uint16_t
nethuns_offvlan_tpid_netmap(__maybe_unused struct nm_pkthdr const *hdr) {
    return 0;
}

static inline uint16_t
nethuns_offvlan_tci_netmap(__maybe_unused struct nm_pkthdr const *hdr) {
    return 0;
}

#ifdef __cplusplus
}
#endif


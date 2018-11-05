#pragma once

#include "internals/stub.h"
#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

    nethuns_socket_t * nethuns_open(struct nethuns_socket_options *opt, char *errbuf);

    int nethuns_bind(nethuns_socket_t * s, const char *dev);

    uint64_t
    nethuns_recv(nethuns_socket_t * s, const nethuns_pkthdr_t **pkthdr, const uint8_t **pkt);

    int nethuns_fd(nethuns_socket_t * s);

    int nethuns_send(nethuns_socket_t * s, const uint8_t *packet, unsigned int len);

    int nethuns_flush(nethuns_socket_t * s);

    int nethuns_close(nethuns_socket_t * s);

    int nethuns_fanout(nethuns_socket_t * s, int group, const char *fanout);

    void nethuns_dump_rings(nethuns_socket_t * s);

    int nethuns_get_stats(nethuns_socket_t * s, struct nethuns_stats *);

    nethuns_pcap_t * nethuns_pcap_open(struct nethuns_socket_options *opt, const char *filename, int mode, char *errbuf);

    int nethuns_pcap_close(nethuns_pcap_t * p);

    uint64_t nethuns_pcap_read(nethuns_pcap_t * p, const nethuns_pkthdr_t **pkthdr, const uint8_t **pkt);
    int nethuns_pcap_write(nethuns_pcap_t * s, nethuns_pkthdr_t const *pkthdr, uint8_t const *packet, unsigned int len);

    //
    // BOOL nethuns_valid_id(uint64_t)
    //
    // TYPE nethuns_tstamp_get_sec(nethuns_pkthdr_t *hdr)
    // TYPE nethuns_tstamp_get_usec(nethuns_pkthdr_t *hdr)
    // TYPE nethuns_tstamp_get_nsec(nethuns_pkthdr_t *hdr)
    //
    // TYPE nethuns_snaplen(nethuns_pkthdr_t *hdr)
    // TYPE nethuns_len(nethuns_pkthdr_t *hdr)
    // TYPE nethuns_rxhash(nethuns_pkthdr_t *hdr)
    // TYPE nethuns_vlan_tci(nethuns_pkthdr_t *hdr)
    //

    void nethuns_perror(char *buf, char *format, ...);

    const char * nethuns_version();


#ifdef __cplusplus
#define nethuns_base(_sock)     (reinterpret_cast<struct nethuns_socket_base *>(_sock))
#else
#define nethuns_base(_sock)     ((struct nethuns_socket_base *)(_sock))
#endif


#define nethuns_error(_sock)    ({nethuns_base(_sock)->errbuf;})

#define nethuns_valid_id(_n)    ((_n) != 0 && (_n) != (uint64_t)-1)
#define nethuns_err_id(_n)      ((_n) == (uint64_t)-1)


#define nethuns_release(_sock, _pktid) do \
{ \
    __atomic_store_n(&nethuns_ring_get_slot(&nethuns_base(_sock)->ring, (_pktid)-1)->inuse, 0, __ATOMIC_RELAXED); \
} while (0)



#ifdef __cplusplus
}
#endif


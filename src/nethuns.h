#pragma once

#include "internals/stub.h"
#include "packet.h"


#ifdef __cplusplus
extern "C" {
#endif

    nethuns_socket_t * nethuns_open(struct nethuns_socket_options *opt);

    int nethuns_bind(nethuns_socket_t * s, const char *dev);

    uint64_t
    nethuns_recv(nethuns_socket_t * s, nethuns_pkthdr_t **pkthdr, const uint8_t **pkt);

    int nethuns_set_consumer(nethuns_socket_t * s, unsigned int numb);

    int nethuns_fd(nethuns_socket_t * s);

    int nethuns_send(nethuns_socket_t * s, const uint8_t *packet, unsigned int len);

    int nethuns_flush(nethuns_socket_t * s);

    int nethuns_close(nethuns_socket_t * s);

    int nethuns_fanout(nethuns_socket_t * s, int group, const char *fanout);

	void nethuns_dump_rings(nethuns_socket_t * s);

	int nethuns_get_stats(nethuns_socket_t * s, struct nethuns_stats *);

    nethuns_pcap_t * nethuns_pcap_open(struct nethuns_socket_options *opt, const char *filename, int mode);
    int nethuns_pcap_close(nethuns_pcap_t * p);
    uint64_t nethuns_pcap_read(nethuns_pcap_t * p, nethuns_pkthdr_t **pkthdr, uint8_t **pkt);
    int nethuns_pcap_write(nethuns_pcap_t * s, nethuns_pkthdr_t *pkthdr, uint8_t const *packet, unsigned int len);


    //
    // BOOL nethuns_valid_id(uint64_t)
    //
    // TYPE nethuns_tstamp_sec(nethuns_pkthdr_t *hdr)
    // TYPE nethuns_tstamp_nsec(nethuns_pkthdr_t *hdr)
    // TYPE nethuns_snaplen(nethuns_pkthdr_t *hdr)
    // TYPE nethuns_len(nethuns_pkthdr_t *hdr)
    // TYPE nethuns_rxhash(nethuns_pkthdr_t *hdr)
    // TYPE nethuns_vlan_tci(nethuns_pkthdr_t *hdr)
    //

#define nethuns_valid_id(n) (n != 0 && n != (uint64_t)-1)
#define nethuns_err_id(n) (n == (uint64_t)-1)


#define nethuns_release(s, pkt_id, consumer_id) \
    { \
        __atomic_store_n(&((struct nethuns_socket_base *)s)->sync.id[consumer_id].value, (pkt_id-1), __ATOMIC_RELEASE); \
    }

#ifdef __cplusplus
}
#endif


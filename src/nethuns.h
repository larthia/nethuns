#pragma once

#include "internals/stub.h"
#include "packet.h"


#ifdef __cplusplus
extern "C" {
#endif

    nethuns_socket_t nethuns_open(unsigned int blocksize, unsigned int numblocks, unsigned int packetsize);

    int nethuns_bind(nethuns_socket_t s, const char *dev);

    uint64_t
    nethuns_recv(nethuns_socket_t s, nethuns_pkthdr_t *pkthdr, const uint8_t **pkt);

    int nethuns_set_consumer(nethuns_socket_t s, unsigned int numb);

    int nethuns_fd(nethuns_socket_t s);

    int nethuns_send(nethuns_socket_t s, const uint8_t *packet, unsigned int len);

    int nethuns_flush(nethuns_socket_t s);

    int nethuns_close(nethuns_socket_t);

    int nethuns_fanout(nethuns_socket_t s, int group, const char *fanout);

    static inline int
    nethuns_release(nethuns_socket_t s, const uint8_t *payload, nethuns_pkthdr_t hdr, uint64_t blockid, unsigned int consumer);


    static inline uint32_t nethuns_tstamp_sec(nethuns_pkthdr_t hdr);
    static inline uint32_t nethuns_tstamp_nsec(nethuns_pkthdr_t hdr);
    static inline uint32_t nethuns_snaplen(nethuns_pkthdr_t hdr);
    static inline uint32_t nethuns_len(nethuns_pkthdr_t hdr);
    static inline uint32_t nethuns_rxhash(nethuns_pkthdr_t hdr);
    static inline uint32_t nethuns_vlan_tci(nethuns_pkthdr_t hdr);

#ifdef __cplusplus
}
#endif


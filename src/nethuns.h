#pragma once

#include "internals/stub.h"

#ifdef __cplusplus
extern "C" {
#endif

    nethuns_socket_t nethuns_open(unsigned int blocksize, unsigned int numblocks, unsigned int packetsize);

    int nethuns_bind(nethuns_socket_t s, const char *dev);

    uint64_t
    nethuns_recv(nethuns_socket_t s, nethuns_pkthdr_t **pkthdr, uint8_t **pkt);

    int nethuns_release(nethuns_socket_t s, nethuns_pkthdr_t *ptkhdr, uint64_t blockid, unsigned int consumer);

    int nethuns_set_consumer(nethuns_socket_t s, unsigned int numb);

    int nethuns_fd(nethuns_socket_t s);

    int nethuns_send(nethuns_socket_t s, uint8_t *packet, unsigned int len);

    int nethuns_flush(nethuns_socket_t s);

    int nethuns_close(nethuns_socket_t);

    int nethuns_fanout(nethuns_socket_t s, int group, const char *fanout);

    static inline int
    nethuns_release(nethuns_socket_t s, nethuns_pkthdr_t *pkt, uint64_t block_id, unsigned int consumer);


#ifdef __cplusplus
}
#endif


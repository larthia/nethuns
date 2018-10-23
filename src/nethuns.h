#pragma once

#include "internals/tpacketv3.h"

#ifdef __cplusplus
extern "C" {
#endif

    nethuns_socket_t nethuns_open(unsigned int blocksize, unsigned int numblocks, unsigned int packetsize);

    int nethuns_bind(nethuns_socket_t s, const char *dev);

    uint64_t
    nethuns_recv(nethuns_socket_t s, nethuns_pkthdr_t **pkthdr, uint8_t **pkt);

    int nethuns_release(nethuns_socket_t s, nethuns_pkthdr_t *ptkhdr, uint64_t blockid, unsigned int consumer);

    int nethuns_flush(nethuns_socket_t s);

    int nethuns_set_consumer(nethuns_socket_t s, unsigned int numb);

    int nethuns_fd(nethuns_socket_t s);

    int nethuns_close(nethuns_socket_t);

#ifdef __cplusplus
}
#endif


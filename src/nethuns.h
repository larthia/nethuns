#pragma once


#include "internals/tpacketv3.h"

nethuns_socket_t nethuns_open(size_t blocksize, size_t numblocks, size_t packetsize);

int nethuns_bind(nethuns_socket_t s, const char *dev);

int nethuns_recv(nethuns_socket_t s, nethuns_pkthdr_t *pkthdr, uint8_t **pkt);

int nethuns_release(nethuns_socket_t s, nethuns_pkthdr_t ptk);

int nethuns_fd(nethuns_socket_t s);

int nethuns_close(nethuns_socket_t);


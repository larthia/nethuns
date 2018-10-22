#pragma once


#include "internals/tpacketv3.h"


struct nethuns_socket * nethuns_open(size_t blocksize, size_t numblocks, size_t packetsize);


int nethuns_close(struct nethuns_socket *);


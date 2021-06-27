#pragma once

#include <stdint.h>
#include "sockets/types.h"

typedef int (*nethuns_filter_t)(void *ctx, const nethuns_pkthdr_t *pkthdr, const uint8_t *pkt);

void nethuns_set_filter(nethuns_socket_t * s, nethuns_filter_t filter, void *ctx);
void nethuns_clear_filter(nethuns_socket_t * s);
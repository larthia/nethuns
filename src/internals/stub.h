#pragma once

#ifdef NETHUNS_USE_TPACKET_V3

#include "internals/tpacket_v3.h"

#define nethuns_open(...)           nethuns_open_tpacket_v3(__VA_ARGS__)
#define nethuns_close(...)          nethuns_close_tpacket_v3(__VA_ARGS__)
#define nethuns_bind(...)           nethuns_bind_tpacket_v3(__VA_ARGS__)
#define nethuns_fd(...)             nethuns_fd_tpacket_v3(__VA_ARGS__)
#define nethuns_recv(...)           nethuns_recv_tpacket_v3(__VA_ARGS__)
#define nethuns_flush(...)          nethuns_flush_tpacket_v3(__VA_ARGS__)
#define nethuns_send(...)           nethuns_send_tpacket_v3(__VA_ARGS__)
#define nethuns_set_consumer(...)   nethuns_set_consumer_tpacket_v3(__VA_ARGS__)
#define nethuns_release(...)        nethuns_release_tpacket_v3(__VA_ARGS__)

#else

#error "Nethuns: socket type not specified!"

#endif

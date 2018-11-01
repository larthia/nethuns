#pragma once

#include "internals/filepcap.h"

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
#define nethuns_fanout(...)         nethuns_fanout_tpacket_v3(__VA_ARGS__)

#define nethuns_tstamp_sec(...)     nethuns_tstamp_sec_tpacket_v3(__VA_ARGS__)
#define nethuns_tstamp_nsec(...)    nethuns_tstamp_nsec_tpacket_v3(__VA_ARGS__)
#define nethuns_snaplen(...)        nethuns_snaplen_tpacket_v3(__VA_ARGS__)
#define nethuns_len(...)            nethuns_len_tpacket_v3(__VA_ARGS__)
#define nethuns_rxhash(...)         nethuns_rxhash_tpacket_v3(__VA_ARGS__)
#define nethuns_vlan_tci(...)       nethuns_vlan_tci_tpacket_v3(__VA_ARGS__)
#define nethuns_dump_rings(...)     nethuns_dump_rings_tpacket_v3(__VA_ARGS__)
#define nethuns_get_stats(...)      nethuns_get_stats_tpacket_v3(__VA_ARGS__)

#else

#error "Nethuns: socket type not specified!"

#endif

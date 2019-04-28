#pragma once

#include "filepcap.h"

#ifdef NETHUNS_USE_TPACKET_V3

#include "tpacket_v3.h"

#define nethuns_open(...)           nethuns_open_tpacket_v3(__VA_ARGS__)
#define nethuns_close(...)          nethuns_close_tpacket_v3(__VA_ARGS__)
#define nethuns_bind(...)           nethuns_bind_tpacket_v3(__VA_ARGS__)
#define nethuns_fd(...)             nethuns_fd_tpacket_v3(__VA_ARGS__)
#define nethuns_recv(...)           nethuns_recv_tpacket_v3(__VA_ARGS__)
#define nethuns_flush(...)          nethuns_flush_tpacket_v3(__VA_ARGS__)
#define nethuns_send(...)           nethuns_send_tpacket_v3(__VA_ARGS__)
#define nethuns_fanout(...)         nethuns_fanout_tpacket_v3(__VA_ARGS__)

#define nethuns_tstamp_sec(...)     nethuns_tstamp_sec_tpacket_v3(__VA_ARGS__)
#define nethuns_tstamp_usec(...)    nethuns_tstamp_usec_tpacket_v3(__VA_ARGS__)
#define nethuns_tstamp_nsec(...)    nethuns_tstamp_nsec_tpacket_v3(__VA_ARGS__)
#define nethuns_tstamp_set_sec(...)     nethuns_tstamp_set_sec_tpacket_v3(__VA_ARGS__)
#define nethuns_tstamp_set_usec(...)    nethuns_tstamp_set_usec_tpacket_v3(__VA_ARGS__)
#define nethuns_tstamp_set_nsec(...)    nethuns_tstamp_set_nsec_tpacket_v3(__VA_ARGS__)

#define nethuns_snaplen(...)        nethuns_snaplen_tpacket_v3(__VA_ARGS__)
#define nethuns_len(...)            nethuns_len_tpacket_v3(__VA_ARGS__)
#define nethuns_set_snaplen(...)    nethuns_set_snaplen_tpacket_v3(__VA_ARGS__)
#define nethuns_set_len(...)        nethuns_set_len_tpacket_v3(__VA_ARGS__)

#define nethuns_rxhash(...)         nethuns_rxhash_tpacket_v3(__VA_ARGS__)
#define nethuns_dump_rings(...)     nethuns_dump_rings_tpacket_v3(__VA_ARGS__)
#define nethuns_stats(...)          nethuns_stats_tpacket_v3(__VA_ARGS__)

#define nethuns_offvlan_tci(...)    nethuns_offvlan_tci_tpacket_v3(__VA_ARGS__)
#define nethuns_offvlan_tpid(...)   nethuns_offvlan_tpid_tpacket_v3(__VA_ARGS__)

#elif defined(NETHUNS_USE_NETMAP)

#include "netmap.h"

#define nethuns_open(...)           nethuns_open_netmap(__VA_ARGS__)
#define nethuns_close(...)          nethuns_close_netmap(__VA_ARGS__)
#define nethuns_bind(...)           nethuns_bind_netmap(__VA_ARGS__)
#define nethuns_fd(...)             nethuns_fd_netmap(__VA_ARGS__)
#define nethuns_recv(...)           nethuns_recv_netmap(__VA_ARGS__)
#define nethuns_flush(...)          nethuns_flush_netmap(__VA_ARGS__)
#define nethuns_send(...)           nethuns_send_netmap(__VA_ARGS__)
#define nethuns_fanout(...)         nethuns_fanout_netmap(__VA_ARGS__)

#define nethuns_tstamp_sec(...)     nethuns_tstamp_sec_netmap(__VA_ARGS__)
#define nethuns_tstamp_usec(...)    nethuns_tstamp_usec_netmap(__VA_ARGS__)
#define nethuns_tstamp_nsec(...)    nethuns_tstamp_nsec_netmap(__VA_ARGS__)
#define nethuns_tstamp_set_sec(...)     nethuns_tstamp_set_sec_netmap(__VA_ARGS__)
#define nethuns_tstamp_set_usec(...)    nethuns_tstamp_set_usec_netmap(__VA_ARGS__)
#define nethuns_tstamp_set_nsec(...)    nethuns_tstamp_set_nsec_netmap(__VA_ARGS__)

#define nethuns_snaplen(...)        nethuns_snaplen_netmap(__VA_ARGS__)
#define nethuns_len(...)            nethuns_len_netmap(__VA_ARGS__)
#define nethuns_set_snaplen(...)    nethuns_set_snaplen_netmap(__VA_ARGS__)
#define nethuns_set_len(...)        nethuns_set_len_netmap(__VA_ARGS__)

#define nethuns_rxhash(...)         nethuns_rxhash_netmap(__VA_ARGS__)
#define nethuns_dump_rings(...)     nethuns_dump_rings_netmap(__VA_ARGS__)
#define nethuns_stats(...)          nethuns_stats_netmap(__VA_ARGS__)

#define nethuns_offvlan_tci(...)    nethuns_offvlan_tci_netmap(__VA_ARGS__)
#define nethuns_offvlan_tpid(...)   nethuns_offvlan_tpid_netmap(__VA_ARGS__)

#elif defined (NETHUNS_USE_DEVPCAP)

#include "devpcap.h"

#define nethuns_open(...)           nethuns_open_devpcap(__VA_ARGS__)
#define nethuns_close(...)          nethuns_close_devpcap(__VA_ARGS__)
#define nethuns_bind(...)           nethuns_bind_devpcap(__VA_ARGS__)
#define nethuns_fd(...)             nethuns_fd_devpcap(__VA_ARGS__)
#define nethuns_recv(...)           nethuns_recv_devpcap(__VA_ARGS__)
#define nethuns_flush(...)          nethuns_flush_devpcap(__VA_ARGS__)
#define nethuns_send(...)           nethuns_send_devpcap(__VA_ARGS__)
#define nethuns_fanout(...)         nethuns_fanout_devpcap(__VA_ARGS__)

#define nethuns_tstamp_sec(...)     nethuns_tstamp_sec_devpcap(__VA_ARGS__)
#define nethuns_tstamp_usec(...)    nethuns_tstamp_usec_devpcap(__VA_ARGS__)
#define nethuns_tstamp_nsec(...)    nethuns_tstamp_nsec_devpcap(__VA_ARGS__)
#define nethuns_tstamp_set_sec(...)     nethuns_tstamp_set_sec_devpcap(__VA_ARGS__)
#define nethuns_tstamp_set_usec(...)    nethuns_tstamp_set_usec_devpcap(__VA_ARGS__)
#define nethuns_tstamp_set_nsec(...)    nethuns_tstamp_set_nsec_devpcap(__VA_ARGS__)

#define nethuns_snaplen(...)        nethuns_snaplen_devpcap(__VA_ARGS__)
#define nethuns_len(...)            nethuns_len_devpcap(__VA_ARGS__)
#define nethuns_set_snaplen(...)    nethuns_set_snaplen_devpcap(__VA_ARGS__)
#define nethuns_set_len(...)        nethuns_set_len_devpcap(__VA_ARGS__)

#define nethuns_dump_rings(...)     nethuns_dump_rings_devpcap(__VA_ARGS__)
#define nethuns_stats(...)          nethuns_stats_devpcap(__VA_ARGS__)

#define nethuns_rxhash(...)         nethuns_rxhash_devpcap(__VA_ARGS__)

#define nethuns_offvlan_tci(...)    nethuns_offvlan_tci_devpcap(__VA_ARGS__)
#define nethuns_offvlan_tpid(...)   nethuns_offvlan_tpid_devpcap(__VA_ARGS__)

#else

#error "Nethuns: socket type not specified!"

#endif

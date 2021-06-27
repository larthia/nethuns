#pragma once

#include "define.h"
#include "vlan.h"

#if !defined NETHUNS_SOCKET
#error NETHUNS_SOCKET is not defined.
#endif

#if NETHUNS_SOCKET == NETHUNS_SOCKET_TPACKET3

#include "sockets/tpacket_v3.h"

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

#elif NETHUNS_SOCKET == NETHUNS_SOCKET_NETMAP

#include "sockets/netmap.h"

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

#elif NETHUNS_SOCKET == NETHUNS_SOCKET_LIBPCAP

#include "sockets/libpcap.h"

#define nethuns_open(...)           nethuns_open_libpcap(__VA_ARGS__)
#define nethuns_close(...)          nethuns_close_libpcap(__VA_ARGS__)
#define nethuns_bind(...)           nethuns_bind_libpcap(__VA_ARGS__)
#define nethuns_fd(...)             nethuns_fd_libpcap(__VA_ARGS__)
#define nethuns_recv(...)           nethuns_recv_libpcap(__VA_ARGS__)
#define nethuns_flush(...)          nethuns_flush_libpcap(__VA_ARGS__)
#define nethuns_send(...)           nethuns_send_libpcap(__VA_ARGS__)
#define nethuns_fanout(...)         nethuns_fanout_libpcap(__VA_ARGS__)

#define nethuns_tstamp_sec(...)     nethuns_tstamp_sec_libpcap(__VA_ARGS__)
#define nethuns_tstamp_usec(...)    nethuns_tstamp_usec_libpcap(__VA_ARGS__)
#define nethuns_tstamp_nsec(...)    nethuns_tstamp_nsec_libpcap(__VA_ARGS__)
#define nethuns_tstamp_set_sec(...)     nethuns_tstamp_set_sec_libpcap(__VA_ARGS__)
#define nethuns_tstamp_set_usec(...)    nethuns_tstamp_set_usec_libpcap(__VA_ARGS__)
#define nethuns_tstamp_set_nsec(...)    nethuns_tstamp_set_nsec_libpcap(__VA_ARGS__)

#define nethuns_snaplen(...)        nethuns_snaplen_libpcap(__VA_ARGS__)
#define nethuns_len(...)            nethuns_len_libpcap(__VA_ARGS__)
#define nethuns_set_snaplen(...)    nethuns_set_snaplen_libpcap(__VA_ARGS__)
#define nethuns_set_len(...)        nethuns_set_len_libpcap(__VA_ARGS__)

#define nethuns_dump_rings(...)     nethuns_dump_rings_libpcap(__VA_ARGS__)
#define nethuns_stats(...)          nethuns_stats_libpcap(__VA_ARGS__)

#define nethuns_rxhash(...)         nethuns_rxhash_libpcap(__VA_ARGS__)

#define nethuns_offvlan_tci(...)    nethuns_offvlan_tci_libpcap(__VA_ARGS__)
#define nethuns_offvlan_tpid(...)   nethuns_offvlan_tpid_libpcap(__VA_ARGS__)

#elif NETHUNS_SOCKET == NETHUNS_SOCKET_XDP

#include "sockets/xdp.h"

#define nethuns_open(...)           nethuns_open_xdp(__VA_ARGS__)
#define nethuns_close(...)          nethuns_close_xdp(__VA_ARGS__)
#define nethuns_bind(...)           nethuns_bind_xdp(__VA_ARGS__)
#define nethuns_fd(...)             nethuns_fd_xdp(__VA_ARGS__)
#define nethuns_recv(...)           nethuns_recv_xdp(__VA_ARGS__)
#define nethuns_flush(...)          nethuns_flush_xdp(__VA_ARGS__)
#define nethuns_send(...)           nethuns_send_xdp(__VA_ARGS__)
#define nethuns_fanout(...)         nethuns_fanout_xdp(__VA_ARGS__)

#define nethuns_tstamp_sec(...)     nethuns_tstamp_sec_xdp(__VA_ARGS__)
#define nethuns_tstamp_usec(...)    nethuns_tstamp_usec_xdp(__VA_ARGS__)
#define nethuns_tstamp_nsec(...)    nethuns_tstamp_nsec_xdp(__VA_ARGS__)
#define nethuns_tstamp_set_sec(...)     nethuns_tstamp_set_sec_xdp(__VA_ARGS__)
#define nethuns_tstamp_set_usec(...)    nethuns_tstamp_set_usec_xdp(__VA_ARGS__)
#define nethuns_tstamp_set_nsec(...)    nethuns_tstamp_set_nsec_xdp(__VA_ARGS__)

#define nethuns_snaplen(...)        nethuns_snaplen_xdp(__VA_ARGS__)
#define nethuns_len(...)            nethuns_len_xdp(__VA_ARGS__)
#define nethuns_set_snaplen(...)    nethuns_set_snaplen_xdp(__VA_ARGS__)
#define nethuns_set_len(...)        nethuns_set_len_xdp(__VA_ARGS__)

#define nethuns_dump_rings(...)     nethuns_dump_rings_xdp(__VA_ARGS__)
#define nethuns_stats(...)          nethuns_stats_xdp(__VA_ARGS__)

#define nethuns_rxhash(...)         nethuns_rxhash_xdp(__VA_ARGS__)

#define nethuns_offvlan_tci(...)    nethuns_offvlan_tci_xdp(__VA_ARGS__)
#define nethuns_offvlan_tpid(...)   nethuns_offvlan_tpid_xdp(__VA_ARGS__)

#endif

static inline uint16_t
nethuns_vlan_tpid_(__maybe_unused nethuns_pkthdr_t const *hdr, const uint8_t *payload)
{
    return nethuns_offvlan_tpid(hdr) ? nethuns_offvlan_tpid(hdr) : nethuns_vlan_tpid(payload);
}

static inline uint16_t
nethuns_vlan_tci_(__maybe_unused nethuns_pkthdr_t const *hdr, const uint8_t *payload)
{
    return nethuns_offvlan_tpid(hdr) ? nethuns_offvlan_tci(hdr) : nethuns_vlan_tci(payload);
}

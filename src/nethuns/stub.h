
// Copyright 2021 Larthia, University of Pisa. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#pragma once

#include "sockets/base.h"
#include "define.h"
#include "vlan.h"
#include "global.h"

#if !defined NETHUNS_SOCKET
#error NETHUNS_SOCKET is not defined.
#endif

#define __NETHUNS_INIT(sock) static __always_inline \
void nethuns_init() \
{ \
    nethuns_init_(sizeof(nethuns_pkthdr_t), sock); \
}

#define __NETHUNS_OPEN(sock) static __always_inline \
nethuns_socket_t * nethuns_open(struct nethuns_socket_options *opt, char *errbuf) \
{ \
    return nethuns_open_ ## sock(opt, errbuf); \
}

#define __NETHUNS_CLOSE(sock) static __always_inline \
int nethuns_close(nethuns_socket_t * s) \
{ \
    return nethuns_close_ ## sock (s); \
}

#define __NETHUNS_BIND(sock) static __always_inline \
int nethuns_bind(nethuns_socket_t * s, const char *dev, int queue) \
{ \
    return nethuns_bind_ ## sock (s, dev, queue); \
}

#define __NETHUNS_CHECK(sock) static __always_inline \
int nethuns_check(size_t hsize, char *errbuf) \
{ \
    return nethuns_check_ ## sock (hsize, errbuf); \
}

#define __NETHUNS_FD(sock) static __always_inline \
int nethuns_fd(__maybe_unused nethuns_socket_t *s) \
{ \
    return nethuns_fd_ ## sock (s); \
}

#define __NETHUNS_RECV(sock) static __always_inline \
uint64_t nethuns_recv(nethuns_socket_t * s, const nethuns_pkthdr_t **pkthdr, const uint8_t **pkt) \
{ \
    return nethuns_recv_ ## sock (s, pkthdr, pkt); \
}

#define __NETHUNS_SEND(sock) static __always_inline \
int nethuns_send(nethuns_socket_t * s, const uint8_t *packet, unsigned int len) \
{ \
    return nethuns_send_ ## sock (s, packet, len); \
}

#define __NETHUNS_FLUSH(sock) static __always_inline \
int nethuns_flush(nethuns_socket_t * s) \
{ \
    return nethuns_flush_ ## sock (s); \
}

#define __NETHUNS_FANOUT(sock) static __always_inline \
int nethuns_fanout(nethuns_socket_t * s, int group, const char *fanout) \
{ \
    return nethuns_fanout_ ## sock (s, group, fanout); \
}

#define __NETHUNS_STATS(sock) static __always_inline \
int nethuns_stats(nethuns_socket_t * s, struct nethuns_stat *st) \
{ \
    return nethuns_stats_ ## sock (s, st); \
}

#define __NETHUNS_DUMP_RINGS(sock) static __always_inline \
void nethuns_dump_rings(nethuns_socket_t * s) \
{ \
    nethuns_dump_rings_ ## sock (s); \
}

#define __NETHUNS_GET_BUF_ADDR(sock) static __always_inline \
uint8_t * nethuns_get_buf_addr(nethuns_socket_t * s, uint64_t pktid) \
{ \
    return nethuns_get_buf_addr_ ## sock (s, pktid); \
}

#define __NETHUNS_PCAP_OPEN(sock) static __always_inline \
nethuns_pcap_t * nethuns_pcap_open(struct nethuns_socket_options *opt, const char *filename, int mode, char *errbuf) \
{ \
    return nethuns_pcap_open_ ## sock (opt, filename, mode, errbuf); \
}

#define __NETHUNS_PCAP_CLOSE(sock) static __always_inline \
int nethuns_pcap_close(nethuns_pcap_t * p) \
{ \
    return nethuns_pcap_close_ ## sock (p); \
}

#define __NETHUNS_PCAP_READ(sock) static __always_inline \
uint64_t nethuns_pcap_read(nethuns_pcap_t * p, const nethuns_pkthdr_t **pkthdr, const uint8_t **pkt) \
{ \
    return nethuns_pcap_read_ ## sock (p, pkthdr, pkt); \
}

#define __NETHUNS_PCAP_STORE(sock) static __always_inline \
int nethuns_pcap_store(nethuns_pcap_t * s, nethuns_pkthdr_t const *pkthdr, uint8_t const *packet, unsigned int len) \
{ \
    return nethuns_pcap_store_ ## sock (s, pkthdr, packet, len); \
}

#define __NETHUNS_PCAP_WRITE(sock) static __always_inline \
int nethuns_pcap_write(nethuns_pcap_t *s, struct nethuns_pcap_pkthdr const *header, uint8_t const *packet, unsigned int len) \
{ \
    return nethuns_pcap_write_ ## sock (s, header, packet, len); \
}

#define __NETHUNS_PCAP_REWIND(sock) static __always_inline \
int nethuns_pcap_rewind(nethuns_pcap_t *p) \
{ \
    return nethuns_pcap_rewind_ ## sock (p); \
}

#define __NETHUNS_PCAP_DUMP_RINGS(sock) static __always_inline \
void nethuns_pcap_dump_rings(nethuns_pcap_t * s) \
{ \
    nethuns_pcap_dump_rings_ ## sock (s); \
}

#define __NETHUNS_TSTAMP_SEC(sock) static __always_inline \
uint32_t nethuns_tstamp_sec(struct pcap_pkthdr const *hdr) \
{ \
    return nethuns_tstamp_sec_ ## sock (hdr); \
}

#define __NETHUNS_TSTAMP_USEC(sock) static __always_inline \
uint32_t nethuns_tstamp_usec(struct pcap_pkthdr const *hdr) \
{ \
    return nethuns_tstamp_usec_ ## sock (hdr); \
}

#define __NETHUNS_TSTAMP_NSEC(sock) static __always_inline \
uint32_t nethuns_tstamp_nsec(struct pcap_pkthdr const *hdr) \
{ \
    return nethuns_tstamp_nsec_ ## sock (hdr); \
}

#define __NETHUNS_TSTAMP_SET_SEC(sock) static __always_inline \
void nethuns_tstamp_set_sec(struct pcap_pkthdr *hdr, uint32_t v) \
{ \
    nethuns_tstamp_set_sec_ ## sock (hdr, v); \
}

#define __NETHUNS_TSTAMP_SET_USEC(sock) static __always_inline \
void nethuns_tstamp_set_usec(struct pcap_pkthdr *hdr, uint32_t v) \
{ \
    nethuns_tstamp_set_usec_ ## sock (hdr, v); \
}

#define __NETHUNS_TSTAMP_SET_NSEC(sock) static __always_inline \
void nethuns_tstamp_set_nsec(struct pcap_pkthdr *hdr, uint32_t v) \
{ \
    nethuns_tstamp_set_nsec_ ## sock (hdr, v); \
}

#define __NETHUNS_SNAPLEN(sock) static __always_inline \
uint32_t nethuns_snaplen(struct pcap_pkthdr const *hdr) \
{ \
    return nethuns_snaplen_ ## sock (hdr); \
}

#define __NETHUNS_LEN(sock) static __always_inline \
uint32_t nethuns_len(struct pcap_pkthdr const *hdr) \
{ \
    return nethuns_len_ ## sock (hdr); \
}

#define __NETHUNS_SET_SNAPLEN(sock) static __always_inline \
void nethuns_set_snaplen(struct pcap_pkthdr *hdr, uint32_t v) \
{ \
    nethuns_set_snaplen_ ## sock (hdr, v); \
}

#define __NETHUNS_SET_LEN(sock) static __always_inline \
void nethuns_set_len(struct pcap_pkthdr *hdr, uint32_t v) \
{ \
    nethuns_set_len_ ## sock (hdr, v); \
}

#define __NETHUNS_RXHASH(sock) static __always_inline \
uint32_t nethuns_rxhash(__maybe_unused struct pcap_pkthdr const *hdr) \
{ \
    return nethuns_rxhash_ ## sock (hdr); \
}

#define __NETHUNS_OFFVLAN_TPID(sock) static __always_inline \
uint16_t nethuns_offvlan_tpid(__maybe_unused struct pcap_pkthdr const *hdr) \
{ \
    return nethuns_offvlan_tpid_ ## sock (hdr); \
}

#define __NETHUNS_OFFVLAN_TCI(sock) static __always_inline \
uint16_t nethuns_offvlan_tci(__maybe_unused struct pcap_pkthdr const *hdr) \
{ \
    return nethuns_offvlan_tci_ ## sock (hdr); \
}

#if NETHUNS_SOCKET == NETHUNS_SOCKET_TPACKET3

#include "sockets/tpacket_v3.h"

__NETHUNS_INIT(NETHUNS_SOCKET_TPACKET3)
__NETHUNS_OPEN(tpacket_v3)
__NETHUNS_CLOSE(tpacket_v3)
__NETHUNS_BIND(tpacket_v3)
__NETHUNS_CHECK(tpacket_v3)
__NETHUNS_FD(tpacket_v3)
__NETHUNS_RECV(tpacket_v3)
__NETHUNS_SEND(tpacket_v3)
__NETHUNS_FLUSH(tpacket_v3)
__NETHUNS_FANOUT(tpacket_v3)
__NETHUNS_STATS(tpacket_v3)
__NETHUNS_DUMP_RINGS(tpacket_v3)
__NETHUNS_GET_BUF_ADDR(tpacket_v3)

__NETHUNS_PCAP_OPEN(tpacket_v3)
__NETHUNS_PCAP_CLOSE(tpacket_v3)
__NETHUNS_PCAP_READ(tpacket_v3)
__NETHUNS_PCAP_WRITE(tpacket_v3)
__NETHUNS_PCAP_STORE(tpacket_v3)
__NETHUNS_PCAP_REWIND(tpacket_v3)

__NETHUNS_TSTAMP_SEC(tpacket_v3)
__NETHUNS_TSTAMP_USEC(tpacket_v3)
__NETHUNS_TSTAMP_NSEC(tpacket_v3)
__NETHUNS_TSTAMP_SET_SEC(tpacket_v3)
__NETHUNS_TSTAMP_SET_USEC(tpacket_v3)
__NETHUNS_TSTAMP_SET_NSEC(tpacket_v3)
__NETHUNS_SNAPLEN(tpacket_v3)
__NETHUNS_LEN(tpacket_v3)
__NETHUNS_SET_SNAPLEN(tpacket_v3)
__NETHUNS_SET_LEN(tpacket_v3)
__NETHUNS_RXHASH(tpacket_v3)
__NETHUNS_OFFVLAN_TCI(tpacket_v3)
__NETHUNS_OFFVLAN_TPID(tpacket_v3)

#elif NETHUNS_SOCKET == NETHUNS_SOCKET_NETMAP

#include "sockets/netmap.h"

__NETHUNS_INIT(NETHUNS_SOCKET_NETMAP)
__NETHUNS_OPEN(netmap)
__NETHUNS_CLOSE(netmap)
__NETHUNS_BIND(netmap)
__NETHUNS_CHECK(netmap)
__NETHUNS_FD(netmap)
__NETHUNS_RECV(netmap)
__NETHUNS_SEND(netmap)
__NETHUNS_FLUSH(netmap)
__NETHUNS_FANOUT(netmap)
__NETHUNS_STATS(netmap)
__NETHUNS_DUMP_RINGS(netmap)
__NETHUNS_GET_BUF_ADDR(netmap)

__NETHUNS_PCAP_OPEN(netmap)
__NETHUNS_PCAP_CLOSE(netmap)
__NETHUNS_PCAP_READ(netmap)
__NETHUNS_PCAP_WRITE(netmap)
__NETHUNS_PCAP_STORE(netmap)
__NETHUNS_PCAP_REWIND(netmap)

__NETHUNS_TSTAMP_SEC(netmap)
__NETHUNS_TSTAMP_USEC(netmap)
__NETHUNS_TSTAMP_NSEC(netmap)
__NETHUNS_TSTAMP_SET_SEC(netmap)
__NETHUNS_TSTAMP_SET_USEC(netmap)
__NETHUNS_TSTAMP_SET_NSEC(netmap)
__NETHUNS_SNAPLEN(netmap)
__NETHUNS_LEN(netmap)
__NETHUNS_SET_SNAPLnetmapEN()
__NETHUNS_SET_LEN(netmap)
__NETHUNS_RXHASH(netmap)
__NETHUNS_OFFVLAN_TCI(netmap)
__NETHUNS_OFFVLAN_TPID(netmap)

#elif NETHUNS_SOCKET == NETHUNS_SOCKET_LIBPCAP

#include "sockets/libpcap.h"

__NETHUNS_INIT(NETHUNS_SOCKET_LIBPCAP)
__NETHUNS_OPEN(libpcap)
__NETHUNS_CLOSE(libpcap)
__NETHUNS_BIND(libpcap)
__NETHUNS_CHECK(libpcap)
__NETHUNS_FD(libpcap)
__NETHUNS_RECV(libpcap)
__NETHUNS_SEND(libpcap)
__NETHUNS_FLUSH(libpcap)
__NETHUNS_FANOUT(libpcap)
__NETHUNS_STATS(libpcap)
__NETHUNS_DUMP_RINGS(libpcap)
__NETHUNS_GET_BUF_ADDR(libpcap)

__NETHUNS_PCAP_OPEN(libpcap)
__NETHUNS_PCAP_CLOSE(libpcap)
__NETHUNS_PCAP_READ(libpcap)
__NETHUNS_PCAP_WRITE(libpcap)
__NETHUNS_PCAP_STORE(libpcap)
__NETHUNS_PCAP_REWIND(libpcap)

__NETHUNS_TSTAMP_SEC(libpcap)
__NETHUNS_TSTAMP_USEC(libpcap)
__NETHUNS_TSTAMP_NSEC(libpcap)
__NETHUNS_TSTAMP_SET_SEC(libpcap)
__NETHUNS_TSTAMP_SET_USEC(libpcap)
__NETHUNS_TSTAMP_SET_NSEC(libpcap)
__NETHUNS_SNAPLEN(libpcap)
__NETHUNS_LEN(libpcap)
__NETHUNS_SET_SNAPLEN(libpcap)
__NETHUNS_SET_LEN(libpcap)
__NETHUNS_RXHASH(libpcap)
__NETHUNS_OFFVLAN_TCI(libpcap)
__NETHUNS_OFFVLAN_TPID(libpcap)

#elif NETHUNS_SOCKET == NETHUNS_SOCKET_XDP

#include "sockets/xdp.h"

__NETHUNS_INIT(NETHUNS_SOCKET_XDP)
__NETHUNS_OPEN(xdp)
__NETHUNS_CLOSE(xdp)
__NETHUNS_BIND(xdp)
__NETHUNS_CHECK(xdp)
__NETHUNS_RECV(xdp)
__NETHUNS_SEND(xdp)
__NETHUNS_FLUSH(xdp)
__NETHUNS_FANOUT(xdp)
__NETHUNS_STATS(xdp)
__NETHUNS_DUMP_RINGS(xdp)
__NETHUNS_GET_BUF_ADDR(xdp)

__NETHUNS_PCAP_OPEN(xdp)
__NETHUNS_PCAP_CLOSE(xdp)
__NETHUNS_PCAP_READ(xdp)
__NETHUNS_PCAP_WRITE(xdp)
__NETHUNS_PCAP_STORE(xdp)
__NETHUNS_PCAP_REWIND(xdp)

__NETHUNS_TSTAMP_SEC(xdp)
__NETHUNS_TSTAMP_USEC(xdp)
__NETHUNS_TSTAMP_NSEC(xdp)
__NETHUNS_TSTAMP_SET_SECxdp()
__NETHUNS_TSTAMP_SET_USEC(xdp)
__NETHUNS_TSTAMP_SET_NSEC(xdp)
__NETHUNS_SNAPLEN(xdp)
__NETHUNS_LEN(xdp)
__NETHUNS_SET_SNAPLEN(xpd)
__NETHUNS_SET_LEN(xpd)
__NETHUNS_RXHASH(xpd)
__NETHUNS_OFFVLAN_TCI(xpd)
__NETHUNS_OFFVLAN_TPID(xpd)


#endif


static __always_inline uint16_t
nethuns_vlan_tpid_(__maybe_unused nethuns_pkthdr_t const *hdr, const uint8_t *payload)
{
    return nethuns_offvlan_tpid(hdr) ? nethuns_offvlan_tpid(hdr) : nethuns_vlan_tpid(payload);
}

static __always_inline uint16_t
nethuns_vlan_tci_(__maybe_unused nethuns_pkthdr_t const *hdr, const uint8_t *payload)
{
    return nethuns_offvlan_tpid(hdr) ? nethuns_offvlan_tci(hdr) : nethuns_vlan_tci(payload);
}

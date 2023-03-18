// Copyright 2021 Larthia, University of Pisa. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#pragma once

#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <stdio.h>

#include "misc/compiler.h"
#include "sockets/base.h"
#include "global.h"
#include "types.h"

#define NETHUNS_GLOBAL \
    void (*__nethuns_fini)() = nethuns_global_fini;

#define nethuns_error(_sock)        ({nethuns_const_socket(_sock)->errbuf;})
#define nethuns_pkt_is_valid(_n)    ((_n + 2) > 2)
#define nethuns_pkt_is_null(_n)     ((_n) == 0)
#define nethuns_pkt_is_ok(_n)       ((_n + 2) >= 2)
#define nethuns_pkt_is_err(_n)      ((_n) == (uint64_t)-1)
#define nethuns_pkt_is_eof(_n)      ((_n) == (uint64_t)-2)

#ifdef __cplusplus
extern "C" {
#endif

    static __always_inline void nethuns_init();

    static __always_inline nethuns_socket_t * nethuns_open(struct nethuns_socket_options *opt, char *errbuf);

    static __always_inline nethuns_socket_t * nethuns_open(struct nethuns_socket_options *opt, char *errbuf);

    static __always_inline int nethuns_close(nethuns_socket_t * s);

    static __always_inline int nethuns_bind(nethuns_socket_t * s, const char *dev, int queue);

    static __always_inline uint64_t nethuns_recv(nethuns_socket_t * s, const nethuns_pkthdr_t **pkthdr, const uint8_t **pkt);

    static __always_inline int nethuns_fd(nethuns_socket_t * s);

    static __always_inline int nethuns_send(nethuns_socket_t * s, const uint8_t *packet, unsigned int len);

    static __always_inline int nethuns_flush(nethuns_socket_t * s);

    static __always_inline int nethuns_fanout(nethuns_socket_t * s, int group, const char *fanout);

    static __always_inline int nethuns_stats(nethuns_socket_t * s, struct nethuns_stat *);

    static __always_inline void nethuns_dump_rings(nethuns_socket_t * s);

    static __always_inline uint8_t * nethuns_get_buf_addr(nethuns_socket_t * s, uint64_t pktid);

    static __always_inline nethuns_pcap_t * nethuns_pcap_open(struct nethuns_socket_options *opt, const char *filename, int mode, char *errbuf);
    static __always_inline int nethuns_pcap_close(nethuns_pcap_t * p);
    static __always_inline uint64_t nethuns_pcap_read(nethuns_pcap_t * p, const nethuns_pkthdr_t **pkthdr, const uint8_t **pkt);
    static __always_inline int nethuns_pcap_store(nethuns_pcap_t * s, nethuns_pkthdr_t const *pkthdr, uint8_t const *packet, unsigned int len);
    static __always_inline int nethuns_pcap_rewind(nethuns_pcap_t *p);
    static __always_inline int nethuns_pcap_write(nethuns_pcap_t *s, struct nethuns_pcap_pkthdr const *header, uint8_t const *packet, unsigned int len);

    static __always_inline uint32_t nethuns_tstamp_sec(nethuns_pkthdr_t const *hdr);
    static __always_inline uint32_t nethuns_tstamp_usec(nethuns_pkthdr_t const *hdr);
    static __always_inline uint32_t nethuns_tstamp_nsec(nethuns_pkthdr_t const *hdr);
    static __always_inline void nethuns_tstamp_set_sec(nethuns_pkthdr_t *hdr, uint32_t v);
    static __always_inline void nethuns_tstamp_set_usec(nethuns_pkthdr_t *hdr, uint32_t v);
    static __always_inline void nethuns_tstamp_set_nsec(nethuns_pkthdr_t *hdr, uint32_t v);
    static __always_inline uint32_t nethuns_snaplen(nethuns_pkthdr_t const *hdr);
    static __always_inline uint32_t nethuns_len(nethuns_pkthdr_t const *hdr);
    static __always_inline void nethuns_set_snaplen(nethuns_pkthdr_t *hdr, uint32_t v);
    static __always_inline void nethuns_set_len(nethuns_pkthdr_t *hdr, uint32_t v);
    static __always_inline uint32_t nethuns_rxhash(__maybe_unused nethuns_pkthdr_t const *hdr);
    static __always_inline uint16_t nethuns_offvlan_tpid(__maybe_unused nethuns_pkthdr_t const *hdr);
    static __always_inline uint16_t nethuns_offvlan_tci(__maybe_unused nethuns_pkthdr_t const *hdr);

    int nethuns_ioctl_if(nethuns_socket_t *s, const char *devname, unsigned long what, uint32_t *flags);

    void nethuns_perror(char *buf, const char *format, ...);

    void nethuns_fprintf(FILE *out, const char *msg, ...);

    const char * nethuns_version();

    int  __nethuns_set_if_promisc(nethuns_socket_t *s, const char *devname);

    int  __nethuns_clear_if_promisc(nethuns_socket_t *s, const char *devname);

    void __nethuns_free_base(nethuns_socket_t *s);

    // filter functions
    //

    static __always_inline char *
    nethuns_dev_queue_name(const char *dev, int queue)
    {
        static __thread char name[IFNAMSIZ+4];
        if (dev == NULL) {
            snprintf(name, IFNAMSIZ+4, "unspec");
        } else if (queue == NETHUNS_ANY_QUEUE) {
            snprintf(name, IFNAMSIZ+4, "%s", dev);
        } else {
            snprintf(name, IFNAMSIZ+4,"%s:%d", dev, queue);
        }
        return name;
    }

    static __always_inline char *
    nethuns_device_name(nethuns_socket_t *s)
    {
        return nethuns_dev_queue_name(nethuns_socket(s)->devname, nethuns_socket(s)->queue);
    }


#ifdef __cplusplus
}

#include <stdexcept>

struct nethuns_exception : public std::runtime_error {

    nethuns_exception(nethuns_socket_t *s, const char *msg)
    : std::runtime_error(msg)
    , sock(s)
    {}

    nethuns_exception(nethuns_socket_t *s)
    : std::runtime_error(nethuns_error(s))
    , sock(s)
    {}

    nethuns_socket_t *sock;
};

#endif

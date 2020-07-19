#pragma once

#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>

#include "util/compiler.h"
#include "sockets/stub.h"
#include "types.h"
#include "global.h"


#define NETHUNS_INIT                                \
    void (*__nethuns_init)() = nethuns_global_init; \
    void (*__nethuns_fini)() = nethuns_global_fini;


#define NETHUNS_ETH_P_8021Q     0x8100
#define NETHUNS_ETH_P_8021AD    0x88A8


#ifdef __cplusplus
extern "C" {
#endif

    nethuns_socket_t * nethuns_open(struct nethuns_socket_options *opt, char *errbuf);

    int nethuns_bind(nethuns_socket_t * s, const char *dev, int queue);

    uint64_t
    nethuns_recv(nethuns_socket_t * s, const nethuns_pkthdr_t **pkthdr, const uint8_t **pkt);

    int nethuns_fd(nethuns_socket_t * s);

    int nethuns_send(nethuns_socket_t * s, const uint8_t *packet, unsigned int len);

    int nethuns_flush(nethuns_socket_t * s);

    int nethuns_close(nethuns_socket_t * s);

    int nethuns_fanout(nethuns_socket_t * s, int group, const char *fanout);

    void nethuns_dump_rings(nethuns_socket_t * s);

    int nethuns_stats(nethuns_socket_t * s, struct nethuns_stats *);

    nethuns_pcap_t * nethuns_pcap_open(struct nethuns_socket_options *opt, const char *filename, int mode, char *errbuf);

    int nethuns_pcap_close(nethuns_pcap_t * p);

    uint64_t nethuns_pcap_read(nethuns_pcap_t * p, const nethuns_pkthdr_t **pkthdr, const uint8_t **pkt);
    int nethuns_pcap_write(nethuns_pcap_t * s, nethuns_pkthdr_t const *pkthdr, uint8_t const *packet, unsigned int len);
    int nethuns_pcap_rewind(nethuns_pcap_t *p);

    int nethuns_ioctl_if(nethuns_socket_t *s, const char *devname, unsigned long what, uint32_t *flags);

    int  __nethuns_set_if_promisc(nethuns_socket_t *s, const char *devname);
    int  __nethuns_clear_if_promisc(nethuns_socket_t *s, const char *devname);
    void __nethuns_free_base(nethuns_socket_t *s);

    //
    // TYPE nethuns_tstamp_sec(nethuns_pkthdr_t *hdr)
    // TYPE nethuns_tstamp_usec(nethuns_pkthdr_t *hdr)
    // TYPE nethuns_tstamp_nsec(nethuns_pkthdr_t *hdr)
    //
    // TYPE nethuns_snaplen(nethuns_pkthdr_t *hdr)
    // TYPE nethuns_len(nethuns_pkthdr_t *hdr)
    // TYPE nethuns_rxhash(nethuns_pkthdr_t *hdr)
    //
    // TYPE nethuns_offvlan_tci(nethuns_pkthdr_t *hdr)
    // TYPE nethuns_offvlan_tpid(nethuns_pkthdr_t *hdr)
    //

    void nethuns_perror(char *buf, char *format, ...);

    const char * nethuns_version();

    // filter functions
    //

    void nethuns_set_filter(nethuns_socket_t * s, nethuns_filter_t filter, void *ctx);
    void nethuns_clear_filter(nethuns_socket_t * s);

#ifdef __cplusplus
#define nethuns_socket(_sock)     (reinterpret_cast<struct nethuns_socket_base *>(_sock))
#else
#define nethuns_socket(_sock)     ((struct nethuns_socket_base *)(_sock))
#endif

#define nethuns_error(_sock)    ({nethuns_socket(_sock)->errbuf;})


#define nethuns_is_valid(_n)    ((_n + 2) > 2)
#define nethuns_is_null(_n)     ((_n) == 0)

#define nethuns_is_ok(_n)       ((_n + 2) >= 2)
#define nethuns_is_err(_n)      ((_n) == (uint64_t)-1)
#define nethuns_is_eof(_n)      ((_n) == (uint64_t)-2)


#define NETHUNS_ERROR           ((uint64_t)-1)
#define NETHUNS_EOF             ((uint64_t)-2)


#define nethuns_release(_sock, _pktid) do \
{ \
    __atomic_store_n(&nethuns_get_ring_slot(&nethuns_socket(_sock)->ring, (_pktid)-1)->inuse, 0, __ATOMIC_RELEASE); \
} while (0)


static inline uint16_t
nethuns_vlan_vid(uint16_t tci)
{
    return (tci & ((1<<13)-1));
}

static inline uint16_t
nethuns_vlan_pcp(uint16_t tci)
{
    return (tci >> 13) & 7;
}

static inline bool
nethuns_vlan_dei(uint16_t tci)
{
    return (tci >> 12) & 1;
}

static inline uint16_t
nethuns_pktvlan_tpid(const uint8_t *payload)
{
    struct ether_header const *eth = (struct ether_header const *)payload;
    if (eth->ether_type == htons(NETHUNS_ETH_P_8021Q) || eth->ether_type == htons(NETHUNS_ETH_P_8021AD))
        return ntohs(eth->ether_type);
    return 0;
}

static inline uint16_t
nethuns_pktvlan_tci(const uint8_t *payload)
{
    struct ether_header const *eth = (struct ether_header const *)payload;
    if (eth->ether_type == htons(NETHUNS_ETH_P_8021Q) || eth->ether_type == htons(NETHUNS_ETH_P_8021AD))
        return ntohs(*(uint16_t const *)(eth+1));
    return 0;
}

static inline uint16_t
nethuns_vlan_tpid(__maybe_unused nethuns_pkthdr_t const *hdr, const uint8_t *payload)
{
    return nethuns_offvlan_tpid(hdr) ? nethuns_offvlan_tpid(hdr) : nethuns_pktvlan_tpid(payload);
}

static inline uint16_t
nethuns_vlan_tci(__maybe_unused nethuns_pkthdr_t const *hdr, const uint8_t *payload)
{
    return nethuns_offvlan_tpid(hdr) ? nethuns_offvlan_tci(hdr) : nethuns_pktvlan_tci(payload);
}


#ifdef __cplusplus
}
#endif


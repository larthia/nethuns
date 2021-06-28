#pragma once

#include <arpa/inet.h>
#include <net/ethernet.h>

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
nethuns_vlan_tpid(const uint8_t *payload)
{
    struct ether_header const *eth = (struct ether_header const *)payload;
    if (eth->ether_type == htons(NETHUNS_ETH_P_8021Q) || eth->ether_type == htons(NETHUNS_ETH_P_8021AD))
        return ntohs(eth->ether_type);
    return 0;
}

static inline uint16_t
nethuns_vlan_tci(const uint8_t *payload)
{
    struct ether_header const *eth = (struct ether_header const *)payload;
    if (eth->ether_type == htons(NETHUNS_ETH_P_8021Q) || eth->ether_type == htons(NETHUNS_ETH_P_8021AD))
        return ntohs(*(uint16_t const *)(eth+1));
    return 0;
}
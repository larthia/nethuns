#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

const int ETH_ALEN      = 6;                /* Octets in one ethernet addr   */
const int ETH_HLEN      = 14;               /* Total octets in header.   */
const int ETH_DATA_LEN  = 1500;             /* Max. octets in payload    */
const int ETH_FRAME_LEN = 1514;             /* Max. octets in frame sans FCS */

struct eth_hdr
{
    unsigned char   dest[ETH_ALEN];     /* destination eth addr */
    unsigned char   source[ETH_ALEN];   /* source ether addr    */
    uint16_t        proto;              /* packet type ID field */
} __attribute__((packed, aligned(2)));


static inline
int ether_ntoa(unsigned char const *addr, char buf[18])
{
    static const char lookup[] = "0123456789abcdef";
    auto x = 0U;
    for(auto i = 0; i < ETH_ALEN; i++)
    {
        buf[x++] = lookup[addr[i] >> 4];
        buf[x++] = lookup[addr[i] & 0xf];
        if (i < (ETH_ALEN-1))
            buf[x++]= ':';
    }
    buf[x] = '\0';
    return x;
}

inline bool
ether_aton(const char * mac_str, unsigned char bytes[6])
{
    unsigned char mac[6];

    if (sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                &mac[0], &mac[1], &mac[2],
                &mac[3], &mac[4], &mac[5]) != 6)
    {
        return false;
    }

    memcpy(bytes, mac, 6);
    return true;
}

#pragma once

#include <nethuns/network/endian.h>
#include <stdint.h>

struct ip6_hdr
{
#if defined(NETHUNS_LITTLE_ENDIAN)
    uint8_t     priority:4,
                version:4;
#elif defined(NETHUNS_BIG_ENDIAN)
    uint8_t     version:4,
                priority:4;
#else
#error "nethuns: adjust your <nethuns/network/endian.h> defines"
#endif

    uint8_t     flow_lbl[3];        /* label */

    uint16_t    plen;
    uint8_t     next_hdr;	        /* next header */
    uint8_t     hop_lim;	        /* hop limit */

    uint8_t     saddr[16];          /* source address */
    uint8_t     daddr[16];          /* destination address */

} __attribute__((packed, aligned(2)));

#pragma once

#include <nethuns/network/endian.h>
#include <string.h>
#include <stdint.h>

#define NETHUNS_IP_RES          0x8000			/* Flag: "Reserved, must be 0"  */
#define NETHUNS_IP_DF           0x4000			/* Flag: "Don't Fragment"       */
#define NETHUNS_IP_MF           0x2000			/* Flag: "More Fragments"       */
#define NETHUNS_IP_FRAG_OFFSET  0x1FFF			/* "Fragment Offset" part       */

struct iphdr
{
#if defined(NETHUNS_LITTLE_ENDIAN)
    unsigned int ihl:4;
    unsigned int version:4;
#elif defined(NETHUNS_BIG_ENDIAN)
    unsigned int version:4;
    unsigned int ihl:4;
#else
#error "nethuns: adjust your <nethuns/network/endian.h> defines"
#endif
    uint8_t  tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
} __attribute__((packed));

struct ipopt
{
    union
    {
        struct
        {
            uint8_t     copied:1;
            uint8_t     class_:2;
            uint8_t     num:5;
        }   field;

        uint8_t value;
    };

    uint8_t len;
};

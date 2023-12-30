#pragma once

#include <nethuns/network/endian.h>

#include <string.h>
#include <stdint.h>

#define NETHUNS_TCP_FIN     (1 << 0)
#define NETHUNS_TCP_SYN     (1 << 1)
#define NETHUNS_TCP_RST     (1 << 2)
#define NETHUNS_TCP_PSH     (1 << 3)
#define NETHUNS_TCP_ACK     (1 << 4)
#define NETHUNS_TCP_URG     (1 << 5)
#define NETHUNS_TCP_ECE     (1 << 6)
#define NETHUNS_TCP_CWR     (1 << 7)

struct tcphdr
{
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack_seq;
#if defined(NETHUNS_LITTLE_ENDIAN)
	uint16_t res1:4;
	uint16_t doff:4;
	uint16_t fin:1;
	uint16_t syn:1;
	uint16_t rst:1;
	uint16_t psh:1;
	uint16_t ack:1;
	uint16_t urg:1;
	uint16_t ece:1;
	uint16_t cwr:1;
#elif defined(NETHUNS_BIG_ENDIAN)
	uint16_t doff:4;
	uint16_t res1:4;
	uint16_t cwr:1;
	uint16_t ece:1;
	uint16_t urg:1;
	uint16_t ack:1;
	uint16_t psh:1;
	uint16_t rst:1;
	uint16_t syn:1;
	uint16_t fin:1;
#else
#error "nethuns: adjust your <nethuns/network/endian.h> defines"
#endif
	uint16_t window;
	uint16_t check;
	uint16_t urg_ptr;

} __attribute__((packed));

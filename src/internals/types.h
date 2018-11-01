#pragma once


#ifdef NETHUNS_USE_TPACKET_V3

typedef struct tpacket_v3_socket nethuns_socket_t;
typedef struct tpacket3_hdr      nethuns_pkthdr_t;

#else

#error "Nethuns: socket type not specified!"

#endif



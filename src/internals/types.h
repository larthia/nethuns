#pragma once


#if defined (NETHUNS_USE_TPACKET_V3)

typedef struct tpacket_v3_socket nethuns_socket_t;
typedef struct tpacket3_hdr      nethuns_pkthdr_t;

#elif defined (NETHUNS_USE_DEVPCAP)

#include <pcap/pcap.h>

typedef struct devpcap_socket    nethuns_socket_t;
typedef struct pcap_pkthdr       nethuns_pkthdr_t;

#else

#error "Nethuns: socket type not specified!"

#endif



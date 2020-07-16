#pragma once

#if defined (NETHUNS_USE_TPACKET_V3)

typedef struct nethuns_socket_tpacket_v3 nethuns_socket_t;
typedef struct tpacket3_hdr              nethuns_pkthdr_t;

#elif defined (NETHUNS_USE_NETMAP)

#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>

typedef struct nethuns_socket_netmap     nethuns_socket_t;
typedef struct nm_pkthdr                 nethuns_pkthdr_t;

#elif defined (NETHUNS_USE_DEVPCAP)

#include <pcap/pcap.h>

typedef struct nethuns_socket_devpcap    nethuns_socket_t;
typedef struct pcap_pkthdr               nethuns_pkthdr_t;

#elif defined (NETHUNS_USE_XDP)

#include "xdp_pkthdr.h"

typedef struct nethuns_socket_xdp    	 nethuns_socket_t;
typedef struct xdp_pkthdr                nethuns_pkthdr_t;

#else

#error "Nethuns: socket type not specified!"

#endif



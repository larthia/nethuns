#pragma once
#include "../define.h"

#if NETHUNS_SOCKET == NETHUNS_SOCKET_TPACKET3

typedef struct nethuns_socket_tpacket_v3 nethuns_socket_t;
typedef struct tpacket3_hdr              nethuns_pkthdr_t;

#elif NETHUNS_SOCKET == NETHUNS_SOCKET_NETMAP

#include <libnetmap.h>

typedef struct nethuns_socket_netmap     nethuns_socket_t;
typedef struct netmap_pkthdr             nethuns_pkthdr_t;

#elif NETHUNS_SOCKET == NETHUNS_SOCKET_LIBPCAP

#include <pcap/pcap.h>

typedef struct nethuns_socket_libpcap    nethuns_socket_t;
typedef struct pcap_pkthdr               nethuns_pkthdr_t;

#elif NETHUNS_SOCKET == NETHUNS_SOCKET_XDP

#include "xdp_pkthdr.h"

typedef struct nethuns_socket_xdp    	 nethuns_socket_t;
typedef struct xdp_pkthdr                nethuns_pkthdr_t;

#else

typedef void nethuns_socket_t;
typedef void nethuns_pkthdr_t;

#endif
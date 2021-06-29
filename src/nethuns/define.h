#pragma once

#define NETHUNS_ERRBUF_SIZE     512
#define NETHUNS_ANY_QUEUE       (-1)

#define NETHUNS_SOCKET_LIBPCAP   0
#define NETHUNS_SOCKET_NETMAP    1
#define NETHUNS_SOCKET_XDP       2
#define NETHUNS_SOCKET_TPACKET3  3

#define NETHUNS_ERROR               ((uint64_t)-1)
#define NETHUNS_EOF                 ((uint64_t)-2)
#define NETHUNS_ETH_P_8021Q         0x8100
#define NETHUNS_ETH_P_8021AD        0x88A8

#define typeof __typeof__


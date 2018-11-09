# pragma once

#include <stdio.h>

#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>

#include "../types.h"


struct nethuns_socket_netmap
{
    struct nethuns_socket_base base;
    struct nm_desc *p;
};

#ifdef __cplusplus
extern "C" {
#endif


#define nethuns_tstamp_get_sec_netmap(hdr)        ({(uint32_t)hdr->ts.tv_sec; })
#define nethuns_tstamp_get_usec_netmap(hdr)       ({(uint32_t)hdr->ts.tv_usec; })
#define nethuns_tstamp_get_nsec_netmap(hdr)       ({(uint32_t)hdr->ts.tv_usec * 1000;})

#define nethuns_tstamp_set_sec_netmap(hdr,v)      ({hdr->ts.tv_sec = v;})
#define nethuns_tstamp_set_usec_netmap(hdr,v)     ({hdr->ts.tv_usec = v;})
#define nethuns_tstamp_set_nsec_netmap(hdr,v)     ({hdr->ts.tv_usec = v/1000;})

#define nethuns_snaplen_netmap(hdr)         (hdr->caplen)
#define nethuns_len_netmap(hdr)             (hdr->len)
#define nethuns_rxhash_netmap(hdr)          (0)
#define nethuns_vlan_tci_netmap(hdr)        (0)


#ifdef __cplusplus
}
#endif


# pragma once

#include <stdio.h>
#include <pcap/pcap.h>

#include "synapse.h"
#include "../types.h"


struct nethuns_socket_devpcap
{
    struct nethuns_socket_base base;

};

#ifdef __cplusplus
extern "C" {
#endif


#define nethuns_tstamp_get_sec_devpcap(hdr)      ({hdr->ts.tv_sec; })
#define nethuns_tstamp_get_usec_devpcap(hdr)     ({hdr->ts.tv_usec; })
#define nethuns_tstamp_get_nsec_devpcap(hdr)     ({hdr->ts.tv_usec * 1000;})

#define nethuns_tstamp_set_sec_devpcap(hdr,v)      ({hdr->ts.tv_sec = v;})
#define nethuns_tstamp_set_usec_devpcap(hdr,v)     ({hdr->ts.tv_usec = v;})
#define nethuns_tstamp_set_nsec_devpcap(hdr,v)     ({hdr->ts.tv_usec = v/1000;})

#define nethuns_snaplen_devpcap(hdr)         (hdr->caplen)
#define nethuns_len_devpcap(hdr)             (hdr->len)
#define nethuns_rxhash_devpcap(hdr)          (0)
#define nethuns_vlan_tci_devpcap(hdr)        (0)


#ifdef __cplusplus
}
#endif


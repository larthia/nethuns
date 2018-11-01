# pragma once

#include <stdio.h>
#include <pcap/pcap.h>

#include "synapse.h"
#include "../types.h"


struct devpcap_socket
{
    struct nethuns_socket_base base;

};

#ifdef __cplusplus
extern "C" {
#endif


#define nethuns_tstamp_sec_devpcap(hdr)      (hdr->tp_sec)
#define nethuns_tstamp_nsec_devpcap(hdr)     (hdr->tp_nsec)
#define nethuns_snaplen_devpcap(hdr)         (hdr->tp_snaplen)
#define nethuns_len_devpcap(hdr)             (hdr->tp_len)
#define nethuns_rxhash_devpcap(hdr)          (hdr->hv1.tp_rxhash)
#define nethuns_vlan_tci_devpcap(hdr)        (hdr->hv1.tp_vlan_tci)


#ifdef __cplusplus
}
#endif


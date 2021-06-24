#include <nethuns/nethuns.h>
#include <stdio.h>
#include <unistd.h>


void dump_packet(nethuns_pkthdr_t const *hdr, const unsigned char *frame)
{
    int i = 0;

    printf("%u:%u snap:%u len:%u offload{tci:%x tpid:%x} packet{tci:%x pid:%x} => [tci:%x tpid:%x vid:%d] rxhash:0x%x| ", nethuns_tstamp_sec(hdr)
                                                                                     , nethuns_tstamp_nsec(hdr)
                                                                                     , nethuns_snaplen(hdr)
                                                                                     , nethuns_len(hdr)
                                                                                     , nethuns_offvlan_tci(hdr)
                                                                                     , nethuns_offvlan_tpid(hdr)
                                                                                     , nethuns_vlan_tci(frame)
                                                                                     , nethuns_vlan_tpid(frame)
                                                                                     , nethuns_vlan_tci_(hdr, frame)
                                                                                     , nethuns_vlan_tpid_(hdr, frame)
                                                                                     , nethuns_vlan_vid(nethuns_vlan_tci_(hdr, frame))
                                                                                     , nethuns_rxhash(hdr));
    for(; i < 14; i++)
    {
        printf("%02x ", frame[i]);
    }
    printf("\n");
}


int
main(int argc, char *argv[])
{
    nethuns_socket_t *s;

    if (argc < 2)
    {
        fprintf(stderr,"usage: %s dev\n", argv[0]);
        return 0;
    }

    struct nethuns_socket_options opt =
    {
        .numblocks       = 4
    ,   .numpackets      = 4096
    ,   .packetsize      = 2048
    ,   .dir             = nethuns_in_out
    ,   .capture         = nethuns_cap_default
    ,   .mode            = nethuns_socket_rx_tx
    ,   .promisc         = true
    ,   .rxhash          = true
    ,   .tx_qdisc_bypass = false
    ,   .xdp_prog        = NULL
   // ,   .xdp_prog        = "/etc/nethuns/net_xdp.o"
    ,   .xdp_prog_sec    = NULL
    };

    char errbuf[NETHUNS_ERRBUF_SIZE];

    s = nethuns_open(&opt, errbuf);
    if (!s)
    {
        fprintf(stderr, "%s\n", errbuf);
        return -1;
    }

    if (nethuns_bind(s, argv[1], NETHUNS_ANY_QUEUE) < 0)
    {
        fprintf(stderr, "%s\n", nethuns_error(s));
        return -1;
    }

    const unsigned char *frame;
    const nethuns_pkthdr_t *pkthdr;

    for(int i =0; i < 50000; i++)
    {
        uint64_t pkt_id;

        if ((pkt_id = nethuns_recv(s, &pkthdr, &frame)))
        {
            dump_packet(pkthdr, frame);
            nethuns_release(s, pkt_id);
        }

        usleep(1);
    }

    printf("done.\n");
    nethuns_close(s);
    return 0;
}

#include <nethuns/nethuns.h>
#include <iostream>
#include <string>
#include <cstring>


void dump_packet(nethuns_pkthdr_t const *hdr, const unsigned char *frame)
{
    int i = 0;

    printf("%u:%u snap:%u len:%u offload{tci:%x tpid:%x} packet{tci:%x pid:%x} => [tci:%x tpid:%x vid:%d] rxhash:0x%x| ", nethuns_tstamp_sec(hdr)
                                                                                     , nethuns_tstamp_nsec(hdr)
                                                                                     , nethuns_snaplen(hdr)
                                                                                     , nethuns_len(hdr)
                                                                                     , nethuns_offvlan_tci(hdr)
                                                                                     , nethuns_offvlan_tpid(hdr)
                                                                                     , nethuns_pktvlan_tci(frame)
                                                                                     , nethuns_pktvlan_tpid(frame)
                                                                                     , nethuns_vlan_tci(hdr, frame)
                                                                                     , nethuns_vlan_tpid(hdr, frame)
                                                                                     , nethuns_vlan_vid(nethuns_vlan_tci(hdr, frame))
                                                                                     , nethuns_rxhash(hdr));
    for(; i < 14; i++)
    {
        printf("%02x ", frame[i]);
    }
    printf("\n");
}


int
main(int argc, char *argv[])
try
{
    if (argc < 3)
    {
        fprintf(stderr,"usage: %s [read file| capture ifname]\n", argv[0]);
        return 0;
    }

    if (strcmp(argv[1], "read") == 0)
    {
        nethuns_pcap_t *p;

        struct nethuns_socket_options opt =
        {
            .numblocks       = 1
        ,   .numpackets      = 1024
        ,   .packetsize      = 2048
        ,   .timeout_ms      = 0
        ,   .dir             = nethuns_in_out
        ,   .capture         = nethuns_cap_default
        ,   .mode            = nethuns_socket_rx_tx
        ,   .promisc         = false
        ,   .rxhash          = false
        ,   .tx_qdisc_bypass = false
        ,   .xdp_prog        = nullptr
        };

        char errbuf[NETHUNS_ERRBUF_SIZE];
        p = nethuns_pcap_open(&opt, argv[2], 0, errbuf);
        if (!p)
        {
            throw std::runtime_error(errbuf);
        }

        const unsigned char *frame;
        const nethuns_pkthdr_t * pkthdr;

        uint64_t pkt_id;

        do
        {
            pkt_id = nethuns_pcap_read(p, &pkthdr, &frame);

            if (nethuns_pktis_valid(pkt_id))
            {
                std::cerr << nethuns_tstamp_sec(pkthdr) << ":" << nethuns_tstamp_nsec(pkthdr) << " caplen:" << nethuns_snaplen(pkthdr) << " len:" << nethuns_len(pkthdr) << ": PACKET!" << std::endl;
            }

            nethuns_release(p, pkt_id);
        }
        while (nethuns_pkt_is_ok(pkt_id));

        if (nethuns_pkt_is_err(pkt_id))
            std::cerr << "err: " << nethuns_error(p) << std::endl;

        nethuns_pcap_close(p);
    }
    else if (strcmp(argv[1], "capture") == 0)
    {
        nethuns_pcap_t *out;

        struct nethuns_socket_options opt =
        {
            .numblocks       = 1
        ,   .numpackets      = 1024
        ,   .packetsize      = 2048
        ,   .timeout_ms      = 0
        ,   .dir             = nethuns_in_out
        ,   .capture         = nethuns_cap_default
        ,   .mode            = nethuns_socket_rx_tx
        ,   .promisc         = false
        ,   .rxhash          = false
        ,   .tx_qdisc_bypass = false
        ,   .xdp_prog        = nullptr
        };

        char errbuf[NETHUNS_ERRBUF_SIZE];

        out = nethuns_pcap_open(&opt, (std::string{argv[2]} + ".pcap").c_str(), 1, errbuf);
        if (!out) {
            throw std::runtime_error(errbuf);
        }

        nethuns_socket_t * in;

        in = nethuns_open(&opt, errbuf);
        if (!in)
        {
            throw std::runtime_error(errbuf);
        }

        if (nethuns_bind(in, argv[2], NETHUNS_ANY_QUEUE) < 0)
        {
            throw nethuns_exception(in);
        }

        for(int i = 0; i < 10;)
        {
            const unsigned char *frame;
            const nethuns_pkthdr_t * pkthdr;

            uint64_t pkt_id;
            if ((pkt_id = nethuns_recv(in, &pkthdr, &frame)))
            {
                dump_packet(pkthdr, frame);
                nethuns_pcap_write(out, pkthdr, frame, nethuns_len(pkthdr));

                nethuns_release(in, pkt_id);
                i++;
            }
        }

        nethuns_pcap_close(out);
        nethuns_close(in);
    }
    else
    {
        std::cerr << argv[0] << ": argument error!" << std::endl;
    }

    return 0;
}
catch(nethuns_exception &e)
{
    if (e.sock) {
        nethuns_close(e.sock);
    }
    std::cerr << e.what() << std::endl;
    return 1;
}
catch(std::exception &e)
{
    std::cerr << e.what() << std::endl;
    return 1;
}

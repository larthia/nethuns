#include <nethuns/nethuns.h>
#include <iostream>
#include <string>
#include <cstring>


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
        ,   .rxhash          = true
        ,   .tx_qdisc_bypass = true
        ,   .dir             = nethuns_in_out
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

            if (nethuns_valid_id(pkt_id))
            {
                std::cerr << nethuns_tstamp_get_sec(pkthdr) << ":" << nethuns_tstamp_get_nsec(pkthdr) << " caplen:" << nethuns_snaplen(pkthdr) << " len:" << nethuns_len(pkthdr) << ": PACKET!" << std::endl;
            }

            nethuns_release(p, pkt_id);
        }
        while (!nethuns_err_id(pkt_id));

        nethuns_pcap_close(p);

    }
    else if (strcmp(argv[1], "capture") == 0)
    {
        nethuns_pcap_t *out;

        struct nethuns_socket_options opt =
        {
            .numblocks       = 2
        ,   .numpackets      = 1024
        ,   .packetsize      = 2048
        ,   .timeout_ms      = 0
        ,   .rxhash          = true
        ,   .tx_qdisc_bypass = true
        ,   .dir             = nethuns_in_out
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

        if (nethuns_bind(in, argv[2]) < 0)
        {
            throw std::runtime_error(nethuns_error(in));
        }

        for(int i = 0; i < 10;)
        {
            const unsigned char *frame;
            const nethuns_pkthdr_t * pkthdr;

            uint64_t pkt_id;
            if ((pkt_id = nethuns_recv(in, &pkthdr, &frame)))
            {
                std::cerr << "WRITE: #" << i << " packet!" << std::endl;
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
catch(std::exception &e)
{
    std::cerr << e.what() << std::endl;
    return 1;
}


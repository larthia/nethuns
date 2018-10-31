#include <nethuns.h>
#include <iostream>
#include <string>


int
main(int argc, char *argv[])
try
{
    if (argc < 2)
    {
        fprintf(stderr,"usage: %s [in|out]\n", argv[0]);
        return 0;
    }

    if (strcmp(argv[1], "in") == 0)
    {
        nethuns_pcap_t *p;

        struct nethuns_socket_options opt =
        {
            .numblocks  = 1
        ,   .numpackets = 1024
        ,   .packetsize = 2048
        ,   .timeout    = 0
        ,   .rxhash     = true
        };

        p = nethuns_pcap_open(&opt, "read.pcap", 0);
        if (!p) {
            throw std::runtime_error("nethuns_pcap_open (read)!");
        }

        nethuns_pcap_close(p);

    }
    else if (strcmp(argv[1], "out") == 0)
    {
        nethuns_pcap_t *out;

        struct nethuns_socket_options opt =
        {
            .numblocks  = 1
        ,   .numpackets = 1024
        ,   .packetsize = 2048
        ,   .timeout    = 1
        ,   .rxhash     = true
        };

        out = nethuns_pcap_open(&opt, "write.pcap", 1);
        if (!out) {
            throw std::runtime_error("nethuns_pcap_open (write)!");
        }

        nethuns_pcap_close(out);
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
}


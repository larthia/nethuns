#include <nethuns/nethuns.h>
#include <stdio.h>

#include <thread>
#include <atomic>
#include <chrono>
#include <iostream>

void dump_packet(nethuns_pkthdr_t *hdr, unsigned char *frame)
{
    int i = 0;

    printf("%u:%u snap:%u len:%u ", nethuns_tstamp_get_sec(hdr)
                                  , nethuns_tstamp_get_nsec(hdr)
                                  , nethuns_snaplen(hdr)
                                  , nethuns_len(hdr));
    for(; i < 14; i++)
    {
        printf("%02x ", frame[i]);
    }

    printf("\n");
}


std::atomic_long total;

void meter()
{
    auto now = std::chrono::system_clock::now();
    for(;;)
    {
        now += std::chrono::seconds(1);
        std::this_thread::sleep_until(now);
        auto x = total.exchange(0);
        std::cout << "pkt/sec: " << x << std::endl;
    }
}


int
main(int argc, char *argv[])
try
{
    if (argc < 2)
    {
        std::cerr << "usage: " << argv[0] << " dev" << std::endl;
        return 0;
    }

    struct nethuns_socket_options opt =
    {
        .numblocks       = 1
    ,   .numpackets      = 65536
    ,   .packetsize      = 2048
    ,   .timeout_ms      = 0
    ,   .dir             = nethuns_in_out
    ,   .promisc         = true
    ,   .rxhash          = false
    ,   .tx_qdisc_bypass = true
    };

    char errbuf[NETHUNS_ERRBUF_SIZE];
    nethuns_socket_t *s = nethuns_open(&opt, NETHUNS_ANY_QUEUE, errbuf);
    if (s == nullptr)
    {
        throw std::runtime_error(errbuf);
    }

    if (nethuns_bind(s, argv[1]) < 0)
    {
        throw std::runtime_error(nethuns_error(s));
    }

    std::thread(meter).detach();

    const unsigned char *frame;
    const nethuns_pkthdr_t *pkthdr;

    uint64_t total2 = 0;
    for(;;)
    {
        uint64_t pkt_id;

        if ((pkt_id = nethuns_recv(s, &pkthdr, &frame)))
        {
            total++;
            total2++;

            if (total2 == 10000000)
            {
                total2 = 0;
                nethuns_dump_rings(s);
            }

            nethuns_release(s, pkt_id);
        }
    }

    nethuns_close(s);
    return 0;
}
catch(std::exception &e)
{
    std::cerr << e.what() << std::endl;
    return 1;
}


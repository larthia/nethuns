#include <nethuns.h>
#include <stdio.h>

#include <thread>
#include <atomic>
#include <chrono>
#include <iostream>

void dump_packet(nethuns_pkthdr_t *hdr, unsigned char *frame)
{
    int i = 0;

    printf("%u:%u snap:%u len:%u mac:%u", hdr->tp_sec, hdr->tp_nsec, hdr->tp_snaplen, hdr->tp_len, hdr->tp_mac);
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
{
    if (argc < 2)
    {
        std::cerr << "usage: " << argv[0] << " dev" << std::endl;
        return 0;
    }

    struct nethuns_socket_options opt =
    {
        .numblocks  = 64
    ,   .numpackets = 2048
    ,   .packetsize = 2048
    ,   .timeout    = 0
    ,   .rxhash     = false
    };

    char errbuf[NETHUNS_ERRBUF_SIZE];
    nethuns_socket_t *s = nethuns_open(&opt, errbuf);
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
    nethuns_pkthdr_t *pkthdr;

    nethuns_set_consumer(s, 1);

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

            nethuns_release(s, pkt_id, 0);
        }
    }

    nethuns_close(s);
    return 0;
}


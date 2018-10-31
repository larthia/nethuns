#include <nethuns.h>
#include <stdio.h>

#include <thread>
#include <atomic>
#include <chrono>
#include <iostream>

void dump_packet(nethuns_pkthdr_t hdr, const unsigned char *frame)
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
    if (argc < 3)
    {
        std::cerr << "usage: " << argv[0] << " in out" << std::endl;
        return 0;
    }

    std::thread(meter).detach();

    struct nethuns_socket_options opt =
    {
        .numblocks  = 4
    ,   .numpackets = 65536
    ,   .packetsize = 2048
    ,   .rxhash     = false
    };

    nethuns_socket_t in = nethuns_open(&opt);

    nethuns_socket_t out = nethuns_open(&opt);


    if (nethuns_bind(in, argv[1]) < 0)
    {
        return -1;
    }

    if (nethuns_bind(out, argv[2]) < 0)
    {
        return -1;
    }

    const unsigned char *frame;
    nethuns_pkthdr_t pkthdr;

    nethuns_set_consumer(in, 1);

    for(;;)
    {
        uint64_t pkt_id;

        if ((pkt_id = nethuns_recv(in, &pkthdr, &frame)))
        {
            total++;

            while (!nethuns_send(out, frame, pkthdr->tp_len))
            { };

            nethuns_release(in, pkt_id, 0);
        }
    }

    nethuns_close(in);
    nethuns_close(out);
    return 0;
}


#include <boost/lockfree/spsc_queue.hpp>
#include <nethuns.h>
#include <stdio.h>

#include <thread>
#include <atomic>
#include <chrono>
#include <iostream>


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



boost::lockfree::spsc_queue<struct nethuns_packet> queue (8192);


int consumer()
{
    for(;;)
    {
        struct nethuns_packet pkt;

        if (queue.pop(pkt)) {
            total++;
            nethuns_release(pkt.socket, pkt.id, 0);
        }
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

    std::thread(meter).detach();

    std::thread(consumer).detach();

    struct nethuns_socket_options opt =
    {
        .numblocks  = 4
    ,   .numpackets = 65536
    ,   .packetsize = 2048
    ,   .timeout    = 0
    ,   .rxhash     = false
    };

    nethuns_socket_t * s = nethuns_open(&opt);

    if (nethuns_bind(s, argv[1]) < 0)
    {
        return -1;
    }

    const unsigned char *frame;
    nethuns_pkthdr_t * pkthdr;

    nethuns_set_consumer(s, 1);

    for(;;)
    {
        uint64_t id;

        if ((id = nethuns_recv(s, &pkthdr, &frame)))
        {
            struct nethuns_packet p { frame, pkthdr, s, id };

            while (!queue.push(p))
            { };
        }
    }

    nethuns_close(s);
    return 0;
}


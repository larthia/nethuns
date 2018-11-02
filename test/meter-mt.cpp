#include <boost/lockfree/spsc_queue.hpp>
#include <nethuns/nethuns.h>
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
try
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
        .numblocks       = 4
    ,   .numpackets      = 65536
    ,   .packetsize      = 2048
    ,   .timeout_ms      = 0
    ,   .rxhash          = false
    ,   .tx_qdisc_bypass = false
    };

     char errbuf[NETHUNS_ERRBUF_SIZE];

    nethuns_socket_t * s = nethuns_open(&opt, errbuf);
    if (!s)
    {
        throw std::runtime_error(errbuf);
    }

    if (nethuns_bind(s, argv[1]) < 0)
    {
        throw std::runtime_error(nethuns_error(s));
    }

    const unsigned char *frame;
    const nethuns_pkthdr_t * pkthdr;

    nethuns_set_consumer(s, 1);

    for(;;)
    {
        uint64_t id;

        if ((id = nethuns_recv(s, &pkthdr, &frame)))
        {
            struct nethuns_packet p { frame, pkthdr, nethuns_base(s), id };

            while (!queue.push(p))
            { };
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


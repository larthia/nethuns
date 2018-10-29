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
            nethuns_release(pkt.socket, pkt.payload, pkt.pkthdr, pkt.block, 0);
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

    nethuns_socket_t s = nethuns_open( 4        /* number of blocks */
                                     , 65536    /* packets per block */
                                     , 2048     /* max packet size */
                                     );

    if (nethuns_bind(s, argv[1]) < 0)
    {
        return -1;
    }

    const unsigned char *frame;
    nethuns_pkthdr_t pkthdr;

    nethuns_set_consumer(s, 1);

    for(;;)
    {
        uint64_t block;

        if ((block = nethuns_recv(s, &pkthdr, &frame)))
        {
            struct nethuns_packet p { frame, pkthdr, s, block };

            while (!queue.push(p))
            { };
        }
    }

    nethuns_close(s);
    return 0;
}


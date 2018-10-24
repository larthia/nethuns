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


struct nethuns_pkt
{
    nethuns_socket_t  sock;
    nethuns_pkthdr_t  *pkthdr;
    uint64_t          block;

};


boost::lockfree::spsc_queue<nethuns_pkt> queue (8192);


int consumer()
{
    for(;;)
    {
        nethuns_pkt pkt;

        if (queue.pop(pkt)) {
            total++;
            nethuns_release(pkt.sock, pkt.pkthdr, pkt.block, 0);
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

    unsigned char *frame;
    nethuns_pkthdr_t *pkthdr;

    nethuns_set_consumer(s, 1);

    for(;;)
    {
        uint64_t block;

        if ((block = nethuns_recv(s, &pkthdr, &frame)))
        {
            nethuns_pkt p { s, pkthdr, block };

            while (!queue.push(p))
            { };
        }
    }

    nethuns_close(s);
    return 0;
}


#include <nethuns.h>
#include <stdio.h>

#include <thread>
#include <atomic>
#include <chrono>
#include <iostream>

void dump_packet(nethuns_pkthdr_t hdr, unsigned char *frame)
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

    std::thread(meter).detach();

    nethuns_socket_t s = nethuns_open( 4        /* number of blocks */
                                     , 8192     /* packets per block */
                                     , 2048     /* max packet size */
                                     );

    if (s == nullptr)
        throw std::runtime_error("nethuns: failed to open socket!");

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
            total++;
            nethuns_release(s, frame, pkthdr, block, 0);
        }
    }

    nethuns_close(s);
    return 0;
}


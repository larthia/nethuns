#include <boost/lockfree/spsc_queue.hpp>
#include <nethuns.h>
#include <stdio.h>

#include <thread>
#include <atomic>
#include <chrono>
#include <iostream>


std::atomic_long total_rcv;
std::atomic_long total_fwd;

void meter()
{
    auto now = std::chrono::system_clock::now();
    for(;;)
    {
        now += std::chrono::seconds(1);
        std::this_thread::sleep_until(now);
        auto r = total_rcv.exchange(0);
        auto f = total_fwd.exchange(0);
        std::cout << "pkt/sec: " << r << " fwd/sec: " << f << std::endl;
    }
}



boost::lockfree::spsc_queue<struct nethuns_packet> queue (131072);


int consumer(std::string dev)
{
    struct nethuns_socket_options opt =
    {
        .numblocks       = 4
    ,   .numpackets      = 65536
    ,   .packetsize      = 2048
    ,   .timeout         = 0
    ,   .rxhash          = false
    ,   .tx_qdisc_bypass = true
    };

    char errbuf[NETHUNS_ERRBUF_SIZE];

    nethuns_socket_t * out = nethuns_open(&opt, errbuf);
    if (!out)
    {
        throw std::runtime_error(errbuf);
    }

    if (nethuns_bind(out, dev.c_str()) < 0)
    {
        throw std::runtime_error(nethuns_error(out));
    }


    for(;;)
    {
        struct nethuns_packet pkt;

        if (queue.pop(pkt)) {
            total_fwd++;

            while (!nethuns_send(out, (uint8_t *)pkt.payload, pkt.pkthdr->tp_len))
            {
            };

            nethuns_release(pkt.socket, pkt.id, 0);
        }
    }

    nethuns_close(out);
}


int
main(int argc, char *argv[])
try
{
    if (argc < 3)
    {
        std::cerr << "usage: " << argv[0] << " in out" << std::endl;
        return 0;
    }

    std::thread(meter).detach();

    std::thread(consumer, std::string{argv[2]}).detach();

    struct nethuns_socket_options opt =
    {
        .numblocks       = 4
    ,   .numpackets      = 65536
    ,   .packetsize      = 2048
    ,   .timeout         = 0
    ,   .rxhash          = false
    ,   .tx_qdisc_bypass = true
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
    nethuns_pkthdr_t * pkthdr;

    nethuns_set_consumer(s, 1);

    for(;;)
    {
        uint64_t id;

        if ((id = nethuns_recv(s, &pkthdr, &frame)))
        {
            total_rcv++;
            struct nethuns_packet p { frame, pkthdr, s, id };

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


#include <boost/lockfree/spsc_queue.hpp>
#include <nethuns/nethuns.h>
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
    ,   .timeout_ms      = 20
    ,   .dir             = nethuns_in_out
    ,   .capture         = nethuns_cap_default
    ,   .mode            = nethuns_socket_rx_tx
    ,   .promisc         = true
    ,   .rxhash          = false
    ,   .tx_qdisc_bypass = true
    ,   .xdp_prog        = nullptr 
    };

    char errbuf[NETHUNS_ERRBUF_SIZE];

    nethuns_socket_t * out = nethuns_open(&opt, errbuf);
    if (!out)
    {
        throw std::runtime_error(errbuf);
    }

    if (nethuns_bind(out, dev.c_str(), NETHUNS_ANY_QUEUE) < 0)
    {
        throw std::runtime_error(nethuns_error(out));
    }


    for(;;)
    {
        struct nethuns_packet pkt;

        if (queue.pop(pkt)) {
            total_fwd++;

        retry:
            while (!nethuns_send(out, pkt.payload, nethuns_len(pkt.pkthdr)))
            {
                nethuns_flush(out);
                goto retry;
            };

            total_fwd++;

            nethuns_release(pkt.sock, pkt.id);
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
    ,   .timeout_ms      = 20
    ,   .dir             = nethuns_in_out
    ,   .capture         = nethuns_cap_default
    ,   .mode            = nethuns_socket_rx_tx
    ,   .promisc         = true
    ,   .rxhash          = false
    ,   .tx_qdisc_bypass = true
    ,   .xdp_prog        = nullptr 
    };

    char errbuf[NETHUNS_ERRBUF_SIZE];

    nethuns_socket_t * s = nethuns_open(&opt, errbuf);
    if (!s)
    {
        throw std::runtime_error(errbuf);
    }

    if (nethuns_bind(s, argv[1], NETHUNS_ANY_QUEUE) < 0)
    {
        throw std::runtime_error(nethuns_error(s));
    }

    const unsigned char *frame;
    const nethuns_pkthdr_t * pkthdr;

    for(;;)
    {
        uint64_t id;

        if ((id = nethuns_recv(s, &pkthdr, &frame)))
        {
            total_rcv++;
            struct nethuns_packet p { frame, pkthdr, nethuns_socket(s), id };

            while (!queue.push(p))
            { };
        }
    }

    nethuns_close(s);
    return 0;
}
catch(nethuns_exception &e)
{
    if (e.sock) {
        nethuns_close(e.sock);
    }
    std::cerr << e.what() << std::endl;
    return 1;
}
catch(std::exception &e)
{
    std::cerr << e.what() << std::endl;
    return 1;
}

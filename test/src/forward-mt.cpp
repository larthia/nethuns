#include <nethuns/queue.h>
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


nethuns_spsc_queue *queue;

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
    ,   .xdp_prog_sec    = nullptr
    ,   .reuse_maps      = false
    ,   .pin_dir         = nullptr
    };

    char errbuf[NETHUNS_ERRBUF_SIZE];

    nethuns_socket_t * out = nethuns_open(&opt, errbuf);
    if (!out)
    {
        throw std::runtime_error(errbuf);
    }

    if (nethuns_bind(out, dev.c_str(), NETHUNS_ANY_QUEUE) < 0)
    {
        throw nethuns_exception(out);
    }


    for(;;)
    {
        auto pkt =  reinterpret_cast<nethuns_packet *>(nethuns_spsc_pop(queue));

        if (pkt) {

            total_fwd++;

        retry:
            while (!nethuns_send(out, pkt->payload, nethuns_len(pkt->pkthdr)))
            {
                nethuns_flush(out);
                goto retry;
            };

            total_fwd++;

            nethuns_release(pkt->sock, pkt->id);
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

    queue = nethuns_spsc_init(65536, sizeof(nethuns_packet)); 
    if (!queue) { 
        throw std::runtime_error("nethuns_spsc: internal error");
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
    ,   .xdp_prog_sec    = nullptr
    ,   .reuse_maps      = false
    ,   .pin_dir         = nullptr
    };

    char errbuf[NETHUNS_ERRBUF_SIZE];

    nethuns_socket_t * s = nethuns_open(&opt, errbuf);
    if (!s)
    {
        throw std::runtime_error(errbuf);
    }

    if (nethuns_bind(s, argv[1], NETHUNS_ANY_QUEUE) < 0)
    {
        throw nethuns_exception(s);
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

            while (!nethuns_spsc_push(queue, &p))
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

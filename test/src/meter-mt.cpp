// Copyright 2021 Larthia, University of Pisa. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#include <nethuns/nethuns.h>
#include <nethuns/queue.h>
#include <nethuns/types.h>

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
        std::cerr << "pkt/sec: " << x << std::endl;
    }
}

nethuns_spsc_queue *queue;

int consumer()
{
    for(;;)
    {
        auto pkt = reinterpret_cast<struct nethuns_packet *>(nethuns_spsc_pop(queue));
        if (pkt) {
            total++;
            nethuns_rx_release(pkt->sock, pkt->id);
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

    nethuns_init();

    queue = nethuns_spsc_init(65536, sizeof(nethuns_packet));
    if (!queue) {
        throw std::runtime_error("nethuns_spsc: internal error");
    }

    std::thread(meter).detach();
    std::thread(consumer).detach();

    struct nethuns_socket_options opt =
    {
        .numblocks       = 64
    ,   .numpackets      = 2048
    ,   .packetsize      = 2048
    ,   .timeout_ms      = 0
    ,   .dir             = nethuns_in_out
    ,   .capture         = nethuns_cap_default
    ,   .mode            = nethuns_socket_rx_tx
    ,   .promisc         = true
    ,   .rxhash          = false
    ,   .tx_qdisc_bypass = true
    ,   .xdp_prog        = nullptr
    ,   .xdp_prog_sec    = nullptr
    ,   .xsk_map_name    = nullptr
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


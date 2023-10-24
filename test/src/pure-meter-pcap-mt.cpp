// Copyright 2021 Larthia, University of Pisa. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#include <nethuns/queue.h>
#include <pcap/pcap.h>
#include <stdio.h>

#include <thread>
#include <atomic>
#include <chrono>
#include <iostream>
#include <cstring>

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


struct pcap_pkt
{
    unsigned char *pkt;
    struct pcap_pkthdr pkthdr;
};


nethuns_spsc_queue *queue;

int consumer()
{
    for(;;)
    {
        auto pkt = reinterpret_cast<pcap_pkt *>(nethuns_spsc_pop(queue));
        if (pkt) {
            total++;
            free((void *)pkt->pkt);
        }
    }
}


int
main(int argc, char *argv[])
try
{
    char errbuf[PCAP_ERRBUF_SIZE];

    if (argc < 2)
    {
        std::cerr << "usage: " << argv[0] << " dev" << std::endl;
        return 0;
    }

    queue = nethuns_spsc_init(65536, sizeof(pcap_pkt));
    if (!queue) {
        throw std::runtime_error("nethuns_spsc: internal error");
    }

    std::thread(meter).detach();
    std::thread(consumer).detach();

    auto s = pcap_open_live(argv[1], 2048, 1, 0, errbuf);

    const unsigned char *frame;
    struct pcap_pkthdr pkthdr;

    for(;;)
    {
        if ((frame = pcap_next(s, &pkthdr)))
        {
            pcap_pkt p { (unsigned char *)malloc(pkthdr.caplen), pkthdr };

            memcpy(p.pkt, frame, pkthdr.caplen);

            while (!nethuns_spsc_push(queue,&p))
            { };
        }

    }

    pcap_close(s);
    return 0;
}
catch(std::exception &e)
{
    std::cerr << e.what() << std::endl;
    return 1;
}

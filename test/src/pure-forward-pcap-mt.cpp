#include <nethuns/queue.h>
#include <nethuns/types.h>
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

int consumer(std::string dev)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    auto out = pcap_open_live(dev.c_str(), 2048, 1, 0, errbuf);

    for(;;)
    {
        auto pkt = reinterpret_cast<pcap_pkt *>(nethuns_spsc_pop(queue));
        if (pkt) {
            total++;

            while (pcap_inject(out, pkt->pkt, pkt->pkthdr.caplen) < 0)
            { };

            free((void *)pkt->pkt);
        }
    }

    pcap_close(out);
}


int
main(int argc, char *argv[])
try
{
    char errbuf[PCAP_ERRBUF_SIZE];

    if (argc < 3)
    {
        std::cerr << "usage: " << argv[0] << " in out" << std::endl;
        return 0;
    }

    queue = nethuns_spsc_init(65536, sizeof(pcap_pkt)); 
    if (!queue) { 
        throw std::runtime_error("nethuns_spsc: internal error");
    }

    std::thread(meter).detach();
    std::thread(consumer, std::string{argv[2]}).detach();

    auto s = pcap_open_live(argv[1], 2048, 1, 0, errbuf);

    const unsigned char *frame;
    struct pcap_pkthdr pkthdr;

    for(;;)
    {
        if ((frame = pcap_next(s, &pkthdr)))
        {
            pcap_pkt p { (unsigned char *)malloc(pkthdr.caplen), pkthdr };

            memcpy(p.pkt, frame, pkthdr.caplen);

            while (!nethuns_spsc_push(queue, &p))
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

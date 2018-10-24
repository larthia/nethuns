#include <pcap/pcap.h>
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


int
main(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];

    if (argc < 3)
    {
        std::cerr << "usage: " << argv[0] << " in out" << std::endl;
        return 0;
    }

    std::thread(meter).detach();

    auto in  = pcap_open_live(argv[1], 2048, 1, 0, errbuf);
    auto out = pcap_open_live(argv[2], 2048, 1, 0, errbuf);


    const unsigned char *frame;
    struct pcap_pkthdr pkthdr;

    for(;;)
    {
        if ((frame = pcap_next(in, &pkthdr)))
        {
            total++;

            while (pcap_inject(out, frame, pkthdr.caplen) < 0)
            { };

        }
    }

    pcap_close(in);
    pcap_close(out);
    return 0;
}


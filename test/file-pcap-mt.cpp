#include <boost/lockfree/spsc_queue.hpp>
#include <nethuns/nethuns.h>
#include <iostream>
#include <string>
#include <cstring>
#include <thread>
#include <atomic>

boost::lockfree::spsc_queue<struct nethuns_packet> queue (8192);

std::atomic_bool stop{false};

int consumer()
{
    struct nethuns_packet pkt;

    for(;;)
    {
        if (queue.pop(pkt))
        {
            std::cout << "FREE: " << pkt.id << std::endl;
            nethuns_release(pkt.sock, pkt.id);
        }

        if (queue.empty() && stop.load(std::memory_order_relaxed))
        {
            return 0;
        }
    }
}


int
main(int argc, char *argv[])
try
{
    if (argc < 2)
    {
        fprintf(stderr,"usage: %s file\n", argv[0]);
        return 0;
    }

    nethuns_pcap_t *p;

    struct nethuns_socket_options opt =
    {
        .numblocks       = 1
    ,   .numpackets      = 1024
    ,   .packetsize      = 2048
    ,   .timeout_ms      = 0
    ,   .rxhash          = true
    ,   .tx_qdisc_bypass = true
    };

    char errbuf[NETHUNS_ERRBUF_SIZE];
    p = nethuns_pcap_open(&opt, argv[1], 0, errbuf);
    if (!p)
    {
        throw std::runtime_error(errbuf);
    }

    const unsigned char *frame;
    const nethuns_pkthdr_t * pkthdr;

    uint64_t pkt_id;

    std::thread t(consumer);

    do
    {
        pkt_id = nethuns_pcap_read(p, &pkthdr, &frame);
        if (nethuns_valid_id(pkt_id))
        {
            struct nethuns_packet hdr { frame, pkthdr, nethuns_base(p), pkt_id };
            while (!queue.push(hdr))
            { };
        }
    }
    while (!nethuns_err_id(pkt_id));

    std::cerr << "head: " << p->base.ring.head << std::endl;

    stop.store(true, std::memory_order_relaxed);

    t.join();

    nethuns_pcap_close(p);

    return 0;
}
catch(std::exception &e)
{
    std::cerr << e.what() << std::endl;
    return 1;
}


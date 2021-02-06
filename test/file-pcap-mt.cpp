#include <nethuns/queue.h>
#include <nethuns/nethuns.h>
#include <iostream>
#include <string>
#include <cstring>
#include <thread>
#include <atomic>

nethuns_spsc_queue *queue;

std::atomic_bool stop{false};

int consumer()
{
    for(;;)
    {
        auto pkt = reinterpret_cast<nethuns_packet *>(nethuns_spsc_pop(queue));
        if (pkt)
        {
            nethuns_release(pkt->sock, pkt->id);
        }

        if (nethuns_spsc_is_empty(queue) && stop.load(std::memory_order_relaxed))
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

    queue = nethuns_spsc_init(65536, sizeof(nethuns_packet));
    if (!queue) {
        throw std::runtime_error("nethuns_spsc: internal error");
    }

    nethuns_pcap_t *p;

    struct nethuns_socket_options opt =
    {
            .numblocks       = 1
        ,   .numpackets      = 1024
        ,   .packetsize      = 2048
        ,   .timeout_ms      = 0
        ,   .dir             = nethuns_in_out
        ,   .capture         = nethuns_cap_default
        ,   .mode            = nethuns_socket_rx_tx
        ,   .promisc         = false
        ,   .rxhash          = false
        ,   .tx_qdisc_bypass = false
        ,   .xdp_prog        = nullptr
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
        if (nethuns_pkt_is_valid(pkt_id))
        {
            struct nethuns_packet hdr { frame, pkthdr, nethuns_socket(p), pkt_id };
            while (!nethuns_spsc_push(queue, &hdr))
            { };
        }
    }
    while (!nethuns_pkt_is_err(pkt_id));

    std::cerr << "head: " << p->base.ring.head << std::endl;

    stop.store(true, std::memory_order_relaxed);

    t.join();

    nethuns_pcap_close(p);

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

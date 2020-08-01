#include <nethuns/nethuns.h>
#include <stdio.h>

#include <thread>
#include <atomic>
#include <chrono>
#include <iostream>


std::atomic_long total;

void meter(nethuns_socket_t *s)
{
    auto now = std::chrono::system_clock::now();
    for(;;)
    {
        now += std::chrono::seconds(1);
        std::this_thread::sleep_until(now);
        auto x = total.exchange(0);

	nethuns_stat stats;

    	nethuns_stats(s, &stats);

    	std::cout << "pkt/sec: " << x << " { rx:" << stats.rx_packets << " tx:" << stats.tx_packets << " drop:" << stats.rx_dropped << " ifdrop:" << stats.rx_if_dropped << " rx_inv:" << stats.rx_invalid << " tx_inv:" << stats.tx_invalid << " freeze:" << stats.freeze << " }" << std::endl;
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

    struct nethuns_socket_options opt =
    {
        .numblocks       = 1
    ,   .numpackets      = 65536
    ,   .packetsize      = 2048
    ,   .timeout_ms      = 0
    ,   .dir             = nethuns_in_out
    ,   .capture         = nethuns_cap_default
    ,   .mode            = nethuns_socket_rx_tx
    ,   .promisc         = true
    ,   .rxhash          = false
    ,   .tx_qdisc_bypass = true
    ,   .xdp_prog        = "/etc/nethuns/net_xdp.o" 
    };

    char errbuf[NETHUNS_ERRBUF_SIZE];
    nethuns_socket_t *s = nethuns_open(&opt, errbuf);
    if (s == nullptr)
    {
        throw std::runtime_error(errbuf);
    }

    if (nethuns_bind(s, argv[1], NETHUNS_ANY_QUEUE) < 0)
    {
        throw std::runtime_error(nethuns_error(s));
    }

    std::thread(meter, s).detach();

    const unsigned char *frame;
    const nethuns_pkthdr_t *pkthdr;

    uint64_t total2 = 0;

    auto start = std::chrono::system_clock::now();

    for (;;)
    {
        uint64_t pkt_id;

        if ((pkt_id = nethuns_recv(s, &pkthdr, &frame)))
        {
            total++;
            total2++;

            if (total2 == 10000000)
            {
                total2 = 0;
                nethuns_dump_rings(s);
            }

            nethuns_release(s, pkt_id);
        }

        if ((std::chrono::system_clock::now() - start) > std::chrono::seconds(5)) {
            break;
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


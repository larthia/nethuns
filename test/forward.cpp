#include <nethuns/nethuns.h>
#include <stdio.h>

#include <thread>
#include <atomic>
#include <chrono>
#include <iostream>

void dump_packet(nethuns_pkthdr_t *hdr, const unsigned char *frame)
{
    int i = 0;

    printf("%u:%u snap:%u len:%u rxhash:0x%x| ", nethuns_tstamp_get_sec(hdr)
                                               , nethuns_tstamp_get_nsec(hdr)
                                               , nethuns_snaplen(hdr)
                                               , nethuns_len(hdr)
                                               , nethuns_rxhash(hdr));
    for(; i < 14; i++)
    {
        printf("%02x ", frame[i]);
    }

    printf("\n");
}


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

    struct nethuns_socket_options in_opt =
    {
        .numblocks       = 4
    ,   .numpackets      = 65536
    ,   .packetsize      = 2048
    ,   .timeout_ms      = 20
    ,   .dir             = nethuns_in_out
    ,   .promisc         = true
    ,   .rxhash          = false
    ,   .tx_qdisc_bypass = true
    };

    struct nethuns_socket_options out_opt =
    {
        .numblocks       = 4
    ,   .numpackets      = 65536
    ,   .packetsize      = 2048
    ,   .timeout_ms      = 20
    ,   .dir             = nethuns_in_out
    ,   .promisc         = true
    ,   .rxhash          = false
    ,   .tx_qdisc_bypass = true
    };

    char errbuf[NETHUNS_ERRBUF_SIZE];

    nethuns_socket_t *in = nethuns_open(&in_opt, errbuf);
    if (!in)
    {
        throw std::runtime_error(errbuf);
    }

    nethuns_socket_t *out = nethuns_open(&out_opt, errbuf);
    if (!out)
    {
        throw std::runtime_error(errbuf);
    }

    if (nethuns_bind(in, argv[1], NETHUNS_ANY_QUEUE) < 0)
    {
        throw std::runtime_error(nethuns_error(in));
    }

    if (nethuns_bind(out, argv[2], NETHUNS_ANY_QUEUE) < 0)
    {
        throw std::runtime_error(nethuns_error(out));
    }

    const unsigned char *frame;
    const nethuns_pkthdr_t *pkthdr;

    for(;;)
    {
        uint64_t pkt_id;

        if ((pkt_id = nethuns_recv(in, &pkthdr, &frame)))
        {
            total_rcv++;

        retry:
            while (!nethuns_send(out, frame, nethuns_len(pkthdr)))
            {
                nethuns_flush(out);
                goto retry;
            };

            total_fwd++;

            nethuns_release(in, pkt_id);
        }
    }

    nethuns_close(in);
    nethuns_close(out);
    return 0;
}
catch(std::exception &e)
{
    std::cerr << e.what() << std::endl;
    return 1;
}


#include <nethuns/nethuns.h>
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
try
{
    static unsigned char payload[34] =
    {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf0, 0xbf, /* L`..UF.. */
        0x97, 0xe2, 0xff, 0xae, 0x08, 0x00, 0x45, 0x00, /* ......E. */
        0x00, 0x54, 0xb3, 0xf9, 0x40, 0x00, 0x40, 0x11, /* .T..@.@. */
        0xf5, 0x32, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, /* .2...... */
        0x07, 0x08
    };

    if (argc < 2)
    {
        std::cerr << "usage: " << argv[0] << " out" << std::endl;
        return 0;
    }

    std::thread(meter).detach();

    struct nethuns_socket_options opt =
    {
        .numblocks       = 8
    ,   .numpackets      = 8
    ,   .packetsize      = 2048
    ,   .timeout_ms      = 0
    ,   .dir             = nethuns_in_out
    ,   .promisc         = false
    ,   .rxhash          = false
    ,   .tx_qdisc_bypass = true
    };

    char errbuf[NETHUNS_ERRBUF_SIZE];

    nethuns_socket_t *out = nethuns_open(&opt, errbuf);
    if (!out)
    {
        throw std::runtime_error(errbuf);
    }

    if (nethuns_bind(out, argv[1]) < 0)
    {
        throw std::runtime_error(nethuns_error(out));
    }


    for(int n = 0; n < 100;n++)
    {
        total++;

        while (nethuns_send(out, payload, 34) <= 0)
        {

        };

    }

    nethuns_flush(out);
    nethuns_close(out);

    return 0;
}
catch(std::exception &e)
{
    std::cerr << e.what() << std::endl;
    return 1;
}


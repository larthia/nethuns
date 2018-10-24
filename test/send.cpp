#include <nethuns.h>
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

    nethuns_socket_t out = nethuns_open( 8        /* number of blocks */
                                       , 8        /* packets per block */
                                       , 2048     /* max packet size */
                                       );


    if (nethuns_bind(out, argv[1]) < 0)
    {
        return -1;
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


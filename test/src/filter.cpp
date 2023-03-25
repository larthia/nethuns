// Copyright 2021 Larthia, University of Pisa. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#include <nethuns/nethuns.h>
#include <stdio.h>

#include <thread>
#include <atomic>
#include <chrono>
#include <iostream>

void dump_packet(nethuns_pkthdr_t const *hdr, const unsigned char *frame)
{
    int i = 0;

    printf("%u:%u snap:%u len:%u offload{tci:%x tpid:%x} packet{tci:%x pid:%x} => [tci:%x tpid:%x vid:%d] rxhash:0x%x| ", nethuns_tstamp_sec(hdr)
                                                                                     , nethuns_tstamp_nsec(hdr)
                                                                                     , nethuns_snaplen(hdr)
                                                                                     , nethuns_len(hdr)
                                                                                     , nethuns_offvlan_tci(hdr)
                                                                                     , nethuns_offvlan_tpid(hdr)
                                                                                     , nethuns_vlan_tci(frame)
                                                                                     , nethuns_vlan_tpid(frame)
                                                                                     , nethuns_vlan_tci_(hdr, frame)
                                                                                     , nethuns_vlan_tpid_(hdr, frame)
                                                                                     , nethuns_vlan_vid(nethuns_vlan_tci_(hdr, frame))
                                                                                     , nethuns_rxhash(hdr));
    for(; i < 34; i++)
    {
        printf("%02x ", frame[i]);
    }
    printf("\n");
}


int simple_filter(void *ctx, const nethuns_pkthdr_t *pkthdr, const uint8_t *pkt)
{
    static int run;
    auto header = (std::string *)ctx;
    printf("filter context (%s)\n", header->c_str());
    run++;
    if (run & 1) {
        return 1; /* pass */
    } else {
        if (run & 3) { /* drop */
            return 0;
        } else {
            return -1; /* virtual packet */
        }
    }
}


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
    if (argc < 2)
    {
        std::cerr << "usage: " << argv[0] << " dev" << std::endl;
        return 0;
    }

    nethuns_init();

    struct nethuns_socket_options opt =
    {
        .numblocks       = 1
    ,   .numpackets      = 65536
    ,   .packetsize      = 2048
    ,   .timeout_ms      = 0
    ,   .dir             = nethuns_in_out
    ,   .capture         = nethuns_cap_default
    ,   .mode            = nethuns_socket_rx_tx
    ,   .timestamp       = true
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
    nethuns_socket_t *s = nethuns_open(&opt, errbuf);
    if (s == nullptr)
    {
        throw std::runtime_error(errbuf);
    }

    if (nethuns_bind(s, argv[1], NETHUNS_ANY_QUEUE) < 0)
    {
        throw nethuns_exception(s);
    }

    std::thread(meter).detach();

    const unsigned char *frame;
    const nethuns_pkthdr_t *pkthdr;

    // set filter...

    std::string ctx = "packet";
    nethuns_set_filter(s, &simple_filter, &ctx);

    for(;;)
    {
        uint64_t pkt_id;

        if ((pkt_id = nethuns_recv(s, &pkthdr, &frame)))
        {
            if (frame) {
                total++;
                dump_packet(pkthdr, frame);
            } else{
                std::cout << "virtal packet!" << std::endl;
            }

            nethuns_rx_release(s, pkt_id);
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

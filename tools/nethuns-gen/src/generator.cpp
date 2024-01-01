#include <cstddef>
#include <cstdlib>
#include <nethuns/network/ether.h>
#include <nethuns/network/icmp.h>
#include <nethuns/network/icmp6.h>
#include <nethuns/network/ipv4.h>
#include <nethuns/network/ipv6.h>
#include <nethuns/network/udp.h>
#include <nethuns/network/tcp.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <chrono>
#include <exception>
#include <iostream>
#include <optional>
#include <random>
#include <thread>
#include <memory>
#include <chrono>
#include <sstream>

#include "hdr/options.hpp"
#include "hdr/generator.hpp"
#include "hdr/packet.hpp"
#include "hdr/rate_limiter.hpp"
#include "hdr/affinity.hpp"

extern std::atomic_bool sig_shutdown;

static inline int
in_cksum(u_short *addr, int len)
{
    int nleft = len;
    u_short *w = addr;
    int sum = 0;
    u_short answer = 0;

    /*
     * Our algorithm is simple, using a 32 bit accumulator (sum), we add
     * sequential 16 bit words to it, and at the end, fold back all the
     * carry bits from the top 16 bits into the lower 16 bits.
     */
    while (nleft > 1)  {
        sum += *w++;
        nleft -= 2;
    }

    /* mop up an odd byte, if necessary */
    if (nleft == 1) {
        *(u_char *)(&answer) = *(u_char *)w ;
        sum += answer;
    }

    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
    sum += (sum >> 16);         /* add carry */
    answer = ~sum;              /* truncate to 16 bits */
    return(answer);
}


template <typename T, typename ...Ts>
auto to_string(bool toggle, T const &x, Ts const &...xs) -> std::string {
    if (toggle) {
        std::stringstream ss;
        ss << x;
        ((ss << " " << xs), ...);
        return ss.str();
    } else {
        return "off";
    }
}


template <bool PKT_LIMIT, bool RANDOMIZER, bool RATE_LIMITER, bool FIX_CHECKSUM, bool PRELOAD>
void pcap_replay(generator &gen, std::shared_ptr<generator_stats> &stats, int th_idx, int num_threads)
{
    char errbuf[std::max(PCAP_ERRBUF_SIZE, NETHUNS_ERRBUF_SIZE)];

    struct pcap_pkthdr *hdr;
    u_char *data;

    std::mt19937 rand_gen;

    // nethuns options
    //

    auto netopt = nethuns_socket_options {
        .numblocks       = 1
    ,   .numpackets      = 2048
    ,   .packetsize      = 2048
    ,   .timeout_ms      = 0
    ,   .dir             = nethuns_in_out
    ,   .capture         = nethuns_cap_zero_copy
    ,   .mode            = nethuns_socket_rx_tx
    ,   .timestamp       = true
    ,   .promisc         = false
    ,   .rxhash          = false
    ,   .tx_qdisc_bypass = true
    ,   .xdp_prog        = nullptr
    ,   .xdp_prog_sec    = nullptr
    ,   .xsk_map_name    = nullptr
    ,   .reuse_maps      = false
    ,   .pin_dir         = nullptr
    };

    //
    // open nethuns sockets

    auto nh = nethuns_open(&netopt, errbuf);
    if (nh == nullptr)
        throw std::runtime_error("nethuns_open:" + std::string(errbuf));

    //
    // bind nethuns sockets to dev, queue

    if (nethuns_bind(nh, gen.dev.c_str(), num_threads > 1 ? th_idx : NETHUNS_ANY_QUEUE) < 0) {
        throw nethuns_exception(nh);
    }

    //
    // translate pcap file

    std::cerr << "nethuns-gen[" << th_idx << "] '" << gen.source << "' -> " << gen.dev << " (rate_limiter:" << to_string(RATE_LIMITER, gen.pkt_rate, "pps") << " speed:" << to_string(RATE_LIMITER, gen.speed) << " preload:" << to_string(PRELOAD, "on") <<  ")" << std::endl;

    auto const period = std::chrono::nanoseconds(1000000000 / gen.pkt_rate);
    rate_limiter<> limiter;

    std::optional<std::chrono::nanoseconds> prev_ts;

    size_t total = 0;

    auto v = [&] {
        if constexpr(PRELOAD) {
            return packet::from_pcap(gen.source.c_str());
        } else {
            return std::vector<packet>{};
        }
    }();

    for (size_t l = 0; l < gen.loops; l++)
    {
        auto now = std::chrono::steady_clock::now();
        prev_ts = std::nullopt;

        auto p = [&] {
            if constexpr(PRELOAD) {
                return std::nullptr_t{};
            } else {
                auto p = pcap_open_offline(gen.source.c_str(), errbuf);
                if (p == nullptr)
                    throw std::runtime_error("pcap_open_offline:" + std::string(errbuf));
                return p;
            }
        }();

        for(size_t i = 0;;++i)
        {
            if constexpr(PRELOAD) {
                if (unlikely(i >= v.size())) {
                    break;
                }

                hdr = &v[i].hdr_;
                data = v[i].data_.get();

            } else {
                auto n = pcap_next_ex(p, &hdr, (u_char const **)&data);
                if (unlikely(n == -2))
                    break;
            }

            auto ip = reinterpret_cast<iphdr *>(data + 14);

            for (auto j = 0; j < gen.amp; j++)
            {
                if constexpr (RANDOMIZER) {
                    for (auto &p : gen.randomize_prefix)
                    {
                        if ((ip->saddr & p.mask) == (p.addr & p.mask))
                        {
                            ip->saddr = p.addr ^ htonl(static_cast<uint32_t>(rand_gen()) & p.mask);
                        }

                        if ((ip->daddr & p.mask) == (p.addr & p.mask))
                        {
                            ip->daddr = p.addr ^ htonl(static_cast<uint32_t>(rand_gen()) & p.mask);
                        }
                    }

                    if constexpr (FIX_CHECKSUM)
                    {
                        ip->check = 0;
                        ip->check = in_cksum(reinterpret_cast<u_short *>(ip), 20);
                    }
                }

                if constexpr (RATE_LIMITER) {
                    auto ts = std::chrono::nanoseconds(hdr->ts.tv_sec * 1000000000 + hdr->ts.tv_usec * 1000);
                    if (likely(prev_ts != std::nullopt)) {
                        auto delta_ts = (ts - *prev_ts)/gen.speed;
                        auto delta = std::max(delta_ts, period);
                        limiter.wait(now + delta, total + j);
                        now = now + delta;
                    }

                    prev_ts = ts;
                }

                // send packet...

                auto res = nethuns_send(nh, data, hdr->caplen);
                if (likely(res > 0)) {
                    stats->packets.fetch_add(1, std::memory_order_relaxed);
                    stats->bytes.fetch_add(hdr->caplen, std::memory_order_relaxed);
                } else if (res == 0) {
                    stats->discarded.fetch_add(1, std::memory_order_relaxed);
                } else {
                    stats->errors.fetch_add(1, std::memory_order_relaxed);
                }
            }

            nethuns_flush(nh);

            total += gen.amp;

            if constexpr (PKT_LIMIT) {
                if (unlikely(total >= gen.max_packets)) {
                    if constexpr(!PRELOAD) {
                        pcap_close(p);
                    }
                    goto done;
                }
            }

            if (unlikely(sig_shutdown.load(std::memory_order_relaxed))) {
                if constexpr(!PRELOAD) {
                    pcap_close(p);
                }
                goto done;
            }
        }

        if constexpr(!PRELOAD) {
            pcap_close(p);
        }
    }

 done:
    nethuns_close(nh);
    std::cerr << "nethuns-gen[" << th_idx << "] '" << gen.source << "' <- done" << std::endl;
}


template <bool PKT_LIMIT, bool RANDOMIZER, bool RATE_LIMITER, bool FIX_CHECKSUM>
void packets_generator(generator &gen, std::shared_ptr<generator_stats> &stats, int th_idx, int num_threads)
{
    char errbuf[std::max(PCAP_ERRBUF_SIZE, NETHUNS_ERRBUF_SIZE)];

    std::mt19937 rand_gen;

    auto pkt = packet::builder(gen.source, gen.pktlen);

    // nethuns options
    //

    auto netopt = nethuns_socket_options {
        .numblocks       = 1
    ,   .numpackets      = 2048
    ,   .packetsize      = 2048
    ,   .timeout_ms      = 0
    ,   .dir             = nethuns_in_out
    ,   .capture         = nethuns_cap_zero_copy
    ,   .mode            = nethuns_socket_rx_tx
    ,   .timestamp       = true
    ,   .promisc         = false
    ,   .rxhash          = false
    ,   .tx_qdisc_bypass = true
    ,   .xdp_prog        = nullptr
    ,   .xdp_prog_sec    = nullptr
    ,   .xsk_map_name    = nullptr
    ,   .reuse_maps      = false
    ,   .pin_dir         = nullptr
    };

    //
    // open nethuns sockets

    auto nh = nethuns_open(&netopt, errbuf);
    if (nh == nullptr)
        throw std::runtime_error("nethuns_open:" + std::string(errbuf));

    //
    // bind nethuns sockets to dev, queue

    if (nethuns_bind(nh, gen.dev.c_str(), num_threads > 1 ? th_idx : NETHUNS_ANY_QUEUE) < 0) {
        throw nethuns_exception(nh);
    }

    std::cerr << "nethuns-gen[" << th_idx << "] '" << gen.source << "' -> " << gen.dev << " (rate_limiter:" << to_string(RATE_LIMITER, gen.pkt_rate, "pps") << ")" << std::endl;

    auto now = std::chrono::steady_clock::now();
    auto period = std::chrono::nanoseconds(1000000000 / gen.pkt_rate);
    rate_limiter<> limiter;

    for(size_t total = 0;;)
    {
        auto ip = reinterpret_cast<iphdr *>(pkt.data_.get() + 14);

        for (auto j = 0; j < gen.amp; j++)
        {
            if constexpr (RANDOMIZER) {
                if (gen.randomize_src_ip)
                {
                    ip->saddr = ip->saddr ^ htonl(static_cast<uint32_t>(rand_gen()) & gen.randomize_src_ip->mask);
                }

                if (gen.randomize_dst_ip)
                {
                    ip->daddr = ip->daddr ^ htonl(static_cast<uint32_t>(rand_gen()) & gen.randomize_dst_ip->mask);
                }

                if constexpr (FIX_CHECKSUM)
                {
                    ip->check = 0;
                    ip->check = in_cksum(reinterpret_cast<u_short *>(ip), 20);
                }
            }

            if constexpr (RATE_LIMITER) {
                limiter.wait(now + period, total + j);
                now = now + period;
            }

            // send packet...

            auto res = nethuns_send(nh, pkt.data_.get(), pkt.len_);
            if (likely(res > 0)) {
                stats->packets.fetch_add(1, std::memory_order_relaxed);
                stats->bytes.fetch_add(60, std::memory_order_relaxed);
            } else if (res == 0) {
                stats->discarded.fetch_add(1, std::memory_order_relaxed);
            } else {
                stats->errors.fetch_add(1, std::memory_order_relaxed);
            }
        }

        nethuns_flush(nh);

        total += gen.amp;

        if constexpr (PKT_LIMIT) {
            if (unlikely(total >= gen.max_packets)) {
                break;
            }
        }

        if (unlikely(sig_shutdown.load(std::memory_order_relaxed))) {
            goto done;
        }
    }

 done:
    nethuns_close(nh);
    std::cerr << "nethuns-gen[" << th_idx << "] '" << gen.source << "' <- done" << std::endl;
}

#define CASE_PCAP_REPLAY(PKT_LIMIT, RANDOMIZER, RATE_LIMITER, FIX_CHECKSUM, PRELOAD) \
    case bitfield(PKT_LIMIT, RANDOMIZER, RATE_LIMITER, FIX_CHECKSUM, PRELOAD): \
        pcap_replay<PKT_LIMIT, RANDOMIZER, RATE_LIMITER, FIX_CHECKSUM, PRELOAD>(local_gen, local_stats, th_idx, opt.generators.size()); \
        break;

#define CASE_PKT_GENERATOR(PKT_LIMIT, RANDOMIZER, RATE_LIMITER, FIX_CHECKSUM) \
    case bitfield(PKT_LIMIT, RANDOMIZER, RATE_LIMITER, FIX_CHECKSUM): \
        packets_generator<PKT_LIMIT, RANDOMIZER, RATE_LIMITER, FIX_CHECKSUM>(local_gen, local_stats, th_idx, opt.generators.size()); \
        break;

int run(const options& opt) {

    std::vector<std::thread> workers;
    workers.reserve(opt.generators.size());

    std::vector<std::shared_ptr<generator_stats>> stats;
    stats.reserve(opt.generators.size());

    auto exceptions = std::make_shared<std::vector<std::exception_ptr>>(opt.generators.size());

    nethuns_init();

    int th_idx = 0;
    for (auto &gen : opt.generators) {

        auto stat = std::make_shared<generator_stats>();

        auto t = std::thread([=, &exceptions] {
            try {

                auto local_gen = std::move(gen);
                auto local_stats = std::move(stat);

                if (local_gen.cpu) {
                    this_thread::affinity(*local_gen.cpu);
                }

                if (local_gen.is_pcap_file()) {
                    switch (bitfield(local_gen.max_packets != std::numeric_limits<size_t>::max(),
                                     local_gen.has_randomizer(),
                                     local_gen.has_rate_limiter() || local_gen.has_speed_control(),
                                     local_gen.fix_checksums,
                                     local_gen.pcap_preload
                                     ))
                    {
                    CASE_PCAP_REPLAY(false, false, false, false, false);
                    CASE_PCAP_REPLAY(true , false, false, false, false);
                    CASE_PCAP_REPLAY(false, true , false, false, false);
                    CASE_PCAP_REPLAY(true , true , false, false, false);
                    CASE_PCAP_REPLAY(false, false, true , false, false);
                    CASE_PCAP_REPLAY(true , false, true , false, false);
                    CASE_PCAP_REPLAY(false, true , true , false, false);
                    CASE_PCAP_REPLAY(true , true , true , false, false);
                    CASE_PCAP_REPLAY(false, false, false, true , false);
                    CASE_PCAP_REPLAY(true , false, false, true , false);
                    CASE_PCAP_REPLAY(false, true , false, true , false);
                    CASE_PCAP_REPLAY(true , true , false, true , false);
                    CASE_PCAP_REPLAY(false, false, true , true , false);
                    CASE_PCAP_REPLAY(true , false, true , true , false);
                    CASE_PCAP_REPLAY(false, true , true , true , false);
                    CASE_PCAP_REPLAY(true , true , true , true , false);
                    CASE_PCAP_REPLAY(false, false, false, false, true );
                    CASE_PCAP_REPLAY(true , false, false, false, true );
                    CASE_PCAP_REPLAY(false, true , false, false, true );
                    CASE_PCAP_REPLAY(true , true , false, false, true );
                    CASE_PCAP_REPLAY(false, false, true , false, true );
                    CASE_PCAP_REPLAY(true , false, true , false, true );
                    CASE_PCAP_REPLAY(false, true , true , false, true );
                    CASE_PCAP_REPLAY(true , true , true , false, true );
                    CASE_PCAP_REPLAY(false, false, false, true , true );
                    CASE_PCAP_REPLAY(true , false, false, true , true );
                    CASE_PCAP_REPLAY(false, true , false, true , true );
                    CASE_PCAP_REPLAY(true , true , false, true , true );
                    CASE_PCAP_REPLAY(false, false, true , true , true );
                    CASE_PCAP_REPLAY(true , false, true , true , true );
                    CASE_PCAP_REPLAY(false, true , true , true , true );
                    CASE_PCAP_REPLAY(true , true , true , true , true );
                    }
                }
                else {
                    switch (bitfield(local_gen.max_packets != std::numeric_limits<size_t>::max(),
                                     local_gen.has_randomizer(),
                                     local_gen.has_rate_limiter(),
                                     local_gen.fix_checksums
                                     ))
                    {
                    CASE_PKT_GENERATOR(false, false, false, false);
                    CASE_PKT_GENERATOR(true , false, false, false);
                    CASE_PKT_GENERATOR(false, true , false, false);
                    CASE_PKT_GENERATOR(true , true , false, false);
                    CASE_PKT_GENERATOR(false, false, true , false);
                    CASE_PKT_GENERATOR(true , false, true , false);
                    CASE_PKT_GENERATOR(false, true , true , false);
                    CASE_PKT_GENERATOR(true , true , true , false);
                    CASE_PKT_GENERATOR(false, false, false, true );
                    CASE_PKT_GENERATOR(true , false, false, true );
                    CASE_PKT_GENERATOR(false, true , false, true );
                    CASE_PKT_GENERATOR(true , true , false, true );
                    CASE_PKT_GENERATOR(false, false, true , true );
                    CASE_PKT_GENERATOR(true , false, true , true );
                    CASE_PKT_GENERATOR(false, true , true , true );
                    CASE_PKT_GENERATOR(true , true , true , true );
                    }
                }
            } catch(std::exception &e) {
                try {
                    throw std::runtime_error("nethuns-gen[" + std::to_string(th_idx) + "]: " + e.what());
                } catch (...) {
                    exceptions->operator[](th_idx) = std::current_exception();
                }
            }
        });

        workers.emplace_back(std::move(t));
        stats.emplace_back(std::move(stat));

        th_idx++;
    }

    auto meter = std::thread([&] {
        size_t packets_prev = 0;
        size_t bytes_prev = 0;

        auto prev = std::chrono::steady_clock::now();

        while (!sig_shutdown.load(std::memory_order_relaxed)) {
            std::this_thread::sleep_for(std::chrono::seconds(1));

            auto now = std::chrono::steady_clock::now();

            auto period = std::chrono::duration_cast<std::chrono::microseconds>(now - prev).count();

            size_t packets = 0;
            size_t bytes = 0;
            size_t errors = 0;
            size_t discarded = 0;

            for (auto &s : stats) {
                packets += s->packets.load(std::memory_order_relaxed);
                bytes += s->bytes.load(std::memory_order_relaxed);
                errors += s->errors.load(std::memory_order_relaxed);
                discarded += s->discarded.load(std::memory_order_relaxed);
            }

            std::cout << "packets:" << packets << "   packets/sec:" << (packets-packets_prev)*1000000/period  << "   bytes:" << bytes << "   Mbps:" << (bytes-bytes_prev)*8.0/period <<"   discarded:" << discarded << "   errors:" << errors << std::endl;

            packets_prev = packets;
            bytes_prev = bytes;
            prev = now;
        }
    });


    for (auto &t : workers) {
        t.join();
    }

    for (auto &e : *exceptions) {
        if (e) {
            sig_shutdown.store(true, std::memory_order_relaxed);
            meter.join();
            std::rethrow_exception(e);
            return 1;
        }
    }

    meter.join();
    return 0;
}

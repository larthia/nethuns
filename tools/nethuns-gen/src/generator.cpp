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
#include "hdr/pretty.hpp"

extern std::atomic_int sig_shutdown;

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
auto to_string_if(bool toggle, T const &x, Ts const &...xs) -> std::string {
    if (toggle) {
        std::stringstream ss;
        ss << x;
        ((ss << xs), ...);
        return ss.str();
    } else {
        return "off";
    }
}

template <bool PKT_LIMIT, bool RANDOMIZER, bool RATE_LIMITER, bool FIX_CHECKSUM, bool PCAP, bool PCAP_PRELOAD>
void packets_generator(generator &gen, std::shared_ptr<generator_stats> &stats, int num_threads)
{
    char errbuf[std::max(PCAP_ERRBUF_SIZE, NETHUNS_ERRBUF_SIZE)];

    struct pcap_pkthdr *hdr;
    u_char *data;

    constexpr bool VECTORIZED = !PCAP || PCAP_PRELOAD;

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

    if (nethuns_bind(nh, gen.dev.c_str(), num_threads > 1 ? gen.id : NETHUNS_ANY_QUEUE) < 0) {
        throw nethuns_exception(nh);
    }

    //
    // translate pcap file

    auto const period = std::chrono::nanoseconds(1000000000 / gen.pkt_rate);

    rate_limiter<> limiter;
    std::optional<std::chrono::nanoseconds> prev_ts;

    auto v = [&] {
        if constexpr(PCAP) {
            if constexpr(PCAP_PRELOAD) {
                return packet::from_pcap(gen.source.c_str());
            } else {
                return std::vector<packet>{};
            }
        } else {
            return packet::builder(gen.source, gen.pktlen);
        }
    }();

    auto randoms = [&] {
        std::mt19937 rand_gen(gen.seed);

        if constexpr (RANDOMIZER) {
            std::vector<uint32_t> randoms;
            randoms.reserve(gen.amp);
            for (auto i = 0; i < gen.amp; i++) {
                randoms.push_back(rand_gen());
            }
            return randoms;
       } else {
            return std::nullopt;
        }
    }();

    // update mac source or destination
    if constexpr (VECTORIZED) {
        for (auto &p : v) {
            if (!gen.mac_source.empty()) {
                p.set_mac_source(gen.mac_source);
            }

            if (!gen.mac_dest.empty()) {
                p.set_mac_dest(gen.mac_dest);
            }
        }
    } else {
        if (!gen.mac_source.empty()) {
            std::cerr << "nethuns-gen[" << gen.id << "] ignoring source MAC setting to " << gen.mac_source << std::endl;
        }
        if (!gen.mac_dest.empty()) {
            std::cerr << "nethuns-gen[" << gen.id << "] ignoring destination MAC setting to " << gen.mac_dest << std::endl;
        }
    }

    std::cerr << "nethuns-gen[" << gen.id << "] " << gen.source << " -> " << gen.dev << " |"
                << " seed:" << gen.seed
                << " rate:" << to_string_if(RATE_LIMITER, gen.pkt_rate, "_pps")
                << " speed:" << to_string_if(RATE_LIMITER, gen.speed)
                << " period:" << period.count() << "_ns"
                << " max_packets:" << to_string_if(PKT_LIMIT, gen.max_packets)
                << " amp:" << to_string_if(gen.amp > 1, gen.amp)
                << " pcap:"  << to_string_if(PCAP, [] {
                    if constexpr (PCAP_PRELOAD) {
                        return "in-memory-preload";
                    } else {
                        return "on-the-fly";
                    }
                }())
                << std::endl;

    size_t total = 0;
    auto now = std::chrono::steady_clock::now();

    for (size_t l = 0; l < gen.loops; l++)
    {
        if constexpr (!VECTORIZED) {
            now = std::chrono::steady_clock::now();
            prev_ts = std::nullopt;
        };

        auto p = [&] {
            if constexpr(VECTORIZED) {
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
            if constexpr(VECTORIZED) {
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

            auto ip = reinterpret_cast<ip_hdr *>(data + 14);

            for (auto j = 0; j < gen.amp; j++)
            {
                if constexpr (RANDOMIZER) {
                    for (auto &p : gen.randomize_prefix)
                    {
                        if ((ip->saddr & p.mask) == p.addr)
                        {
                            ip->saddr = p.addr ^ htonl(static_cast<uint32_t>(randoms[j]) & p.mask);
                            uint16_t *r = reinterpret_cast<uint16_t *>(data);
                            r[4] ^= static_cast<uint16_t>(randoms[j] >> 16);
                            r[5] ^= static_cast<uint16_t>(randoms[j]);
                        }

                        if ((ip->daddr & p.mask) == p.addr)
                        {
                            ip->daddr = p.addr ^ htonl(static_cast<uint32_t>(randoms[j]) & p.mask);
                            uint16_t *r = reinterpret_cast<uint16_t *>(data);
                            r[1] ^= static_cast<uint16_t>(randoms[j] >> 16);
                            r[2] ^= static_cast<uint16_t>(randoms[j]);
                        }
                    }

                    if constexpr (FIX_CHECKSUM)
                    {
                        ip->check = 0;
                        ip->check = in_cksum(reinterpret_cast<u_short *>(ip), 20);
                    }
                }

                if constexpr (RATE_LIMITER) {
                    if (PCAP) {
                        auto ts = std::chrono::nanoseconds(hdr->ts.tv_sec * 1000000000 + hdr->ts.tv_usec * 1000);
                        if (likely(prev_ts != std::nullopt)) {
                            auto delta_ts = (ts - *prev_ts)/gen.speed;
                            auto delta = std::max(delta_ts, period);
                            limiter.wait(now + delta, total + j);
                            now = now + delta;
                        }

                        prev_ts = ts;
                    } else {
                        limiter.wait(now + period, total + j);
                        now = now + period;
                    }
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
                    if constexpr(!VECTORIZED) {
                        pcap_close(p);
                    }
                    goto done;
                }
            }
        }

        if (unlikely(sig_shutdown.load(std::memory_order_relaxed) > 0)) {
            if constexpr(!VECTORIZED) {
                pcap_close(p);
            }
            goto done;
        }

        if constexpr(!VECTORIZED) {
            pcap_close(p);
        }
    }

 done:
    nethuns_close(nh);
    std::cerr << "nethuns-gen[" << gen.id << "] " << gen.source << " <- done" << std::endl;
}


#define CASE_PACKETS_GENERATOR(PKT_LIMIT, RANDOMIZER, RATE_LIMITER, FIX_CHECKSUM, IS_PCAP,PRELOAD) \
    case bitfield(PKT_LIMIT, RANDOMIZER, RATE_LIMITER, FIX_CHECKSUM, IS_PCAP, PRELOAD): \
        packets_generator<PKT_LIMIT, RANDOMIZER, RATE_LIMITER, FIX_CHECKSUM, IS_PCAP, PRELOAD>(local_gen, local_stats, opt.generators.size()); \
        break;


int run(const options& opt) {

    std::vector<std::thread> workers;
    workers.reserve(opt.generators.size());

    std::vector<std::shared_ptr<generator_stats>> stats;
    stats.reserve(opt.generators.size());

    auto exceptions = std::make_shared<std::vector<std::exception_ptr>>(opt.generators.size());

    nethuns_init();

    for (auto &gen : opt.generators) {

        auto stat = std::make_shared<generator_stats>();

        auto t = std::thread([=, &exceptions] {

            auto local_gen = std::move(gen);
            auto local_stats = std::move(stat);

            try {

                if (local_gen.cpu) {
                    this_thread::affinity(*local_gen.cpu);
                }

                switch (bitfield(local_gen.max_packets != std::numeric_limits<size_t>::max(),
                                 local_gen.has_randomizer(),
                                 local_gen.has_rate_limiter() || local_gen.has_speed_control(),
                                 local_gen.fix_checksums,
                                 local_gen.is_pcap_file(),
                                 local_gen.pcap_preload
                                 ))
                {
                CASE_PACKETS_GENERATOR(false, false, false, false, false, true );
                CASE_PACKETS_GENERATOR(true , false, false, false, false, true );
                CASE_PACKETS_GENERATOR(false, true , false, false, false, true );
                CASE_PACKETS_GENERATOR(true , true , false, false, false, true );
                CASE_PACKETS_GENERATOR(false, false, true , false, false, true );
                CASE_PACKETS_GENERATOR(true , false, true , false, false, true );
                CASE_PACKETS_GENERATOR(false, true , true , false, false, true );
                CASE_PACKETS_GENERATOR(true , true , true , false, false, true );
                CASE_PACKETS_GENERATOR(false, false, false, true , false, true );
                CASE_PACKETS_GENERATOR(true , false, false, true , false, true );
                CASE_PACKETS_GENERATOR(false, true , false, true , false, true );
                CASE_PACKETS_GENERATOR(true , true , false, true , false, true );
                CASE_PACKETS_GENERATOR(false, false, true , true , false, true );
                CASE_PACKETS_GENERATOR(true , false, true , true , false, true );
                CASE_PACKETS_GENERATOR(false, true , true , true , false, true );
                CASE_PACKETS_GENERATOR(true , true , true , true , false, true );
                CASE_PACKETS_GENERATOR(false, false, false, false, true , true );
                CASE_PACKETS_GENERATOR(true , false, false, false, true , true );
                CASE_PACKETS_GENERATOR(false, true , false, false, true , true );
                CASE_PACKETS_GENERATOR(true , true , false, false, true , true );
                CASE_PACKETS_GENERATOR(false, false, true , false, true , true );
                CASE_PACKETS_GENERATOR(true , false, true , false, true , true );
                CASE_PACKETS_GENERATOR(false, true , true , false, true , true );
                CASE_PACKETS_GENERATOR(true , true , true , false, true , true );
                CASE_PACKETS_GENERATOR(false, false, false, true , true , true );
                CASE_PACKETS_GENERATOR(true , false, false, true , true , true );
                CASE_PACKETS_GENERATOR(false, true , false, true , true , true );
                CASE_PACKETS_GENERATOR(true , true , false, true , true , true );
                CASE_PACKETS_GENERATOR(false, false, true , true , true , true );
                CASE_PACKETS_GENERATOR(true , false, true , true , true , true );
                CASE_PACKETS_GENERATOR(false, true , true , true , true , true );
                CASE_PACKETS_GENERATOR(true , true , true , true , true , true );
                CASE_PACKETS_GENERATOR(false, false, false, false, false, false );
                CASE_PACKETS_GENERATOR(true , false, false, false, false, false );
                CASE_PACKETS_GENERATOR(false, true , false, false, false, false );
                CASE_PACKETS_GENERATOR(true , true , false, false, false, false );
                CASE_PACKETS_GENERATOR(false, false, true , false, false, false );
                CASE_PACKETS_GENERATOR(true , false, true , false, false, false );
                CASE_PACKETS_GENERATOR(false, true , true , false, false, false );
                CASE_PACKETS_GENERATOR(true , true , true , false, false, false );
                CASE_PACKETS_GENERATOR(false, false, false, true , false, false );
                CASE_PACKETS_GENERATOR(true , false, false, true , false, false );
                CASE_PACKETS_GENERATOR(false, true , false, true , false, false );
                CASE_PACKETS_GENERATOR(true , true , false, true , false, false );
                CASE_PACKETS_GENERATOR(false, false, true , true , false, false );
                CASE_PACKETS_GENERATOR(true , false, true , true , false, false );
                CASE_PACKETS_GENERATOR(false, true , true , true , false, false );
                CASE_PACKETS_GENERATOR(true , true , true , true , false, false );
                CASE_PACKETS_GENERATOR(false, false, false, false, true , false );
                CASE_PACKETS_GENERATOR(true , false, false, false, true , false );
                CASE_PACKETS_GENERATOR(false, true , false, false, true , false );
                CASE_PACKETS_GENERATOR(true , true , false, false, true , false );
                CASE_PACKETS_GENERATOR(false, false, true , false, true , false );
                CASE_PACKETS_GENERATOR(true , false, true , false, true , false );
                CASE_PACKETS_GENERATOR(false, true , true , false, true , false );
                CASE_PACKETS_GENERATOR(true , true , true , false, true , false );
                CASE_PACKETS_GENERATOR(false, false, false, true , true , false );
                CASE_PACKETS_GENERATOR(true , false, false, true , true , false );
                CASE_PACKETS_GENERATOR(false, true , false, true , true , false );
                CASE_PACKETS_GENERATOR(true , true , false, true , true , false );
                CASE_PACKETS_GENERATOR(false, false, true , true , true , false );
                CASE_PACKETS_GENERATOR(true , false, true , true , true , false );
                CASE_PACKETS_GENERATOR(false, true , true , true , true , false );
                CASE_PACKETS_GENERATOR(true , true , true , true , true , false );
                }

            } catch(std::exception &e) {
                try {
                    throw std::runtime_error("nethuns-gen[" + std::to_string(local_gen.id) + "]: " + e.what());
                } catch (...) {
                    exceptions->operator[](local_gen.id) = std::current_exception();
                }
            }
        });

        workers.emplace_back(std::move(t));
        stats.emplace_back(std::move(stat));
    }

    auto meter = std::thread([&] {
        size_t packets_prev = 0;
        size_t bytes_prev = 0;

        auto prev = std::chrono::steady_clock::now();

        while (sig_shutdown.load(std::memory_order_relaxed) == 0)  {
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

            std::cout << "packets:" << packets << "  packets/sec:" << pretty_number((packets-packets_prev)*1000000.0/period) << "  bps:" << pretty_number((bytes-bytes_prev)*8.0) <<"  discarded:" << discarded << "  errors:" << errors << std::endl;

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
            sig_shutdown.fetch_add(1, std::memory_order_relaxed);
            meter.join();
            std::rethrow_exception(e);
            return 1;
        }
    }

    sig_shutdown.fetch_add(1, std::memory_order_relaxed);
    meter.join();
    return 0;
}

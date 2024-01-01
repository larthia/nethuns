#pragma once

#include <nethuns/nethuns.h>

#include <cstddef>
#include <string>
#include <limits>
#include <vector>
#include <filesystem>
#include <optional>
#include <atomic>

#include "hdr/netaddr.hpp"

struct generator
{
    std::string source;
    std::string dev;
    std::optional<int> cpu = std::nullopt;

    int amp = 1;
    int speed = 1;

    std::size_t max_packets = std::numeric_limits<size_t>::max();
    std::size_t pkt_rate    = std::numeric_limits<size_t>::max();
    std::size_t loops       = std::numeric_limits<size_t>::max();
    std::optional<uint16_t> pktlen = std::nullopt;

    std::optional<netaddr> randomize_src_ip = std::nullopt;
    std::optional<netaddr> randomize_dst_ip = std::nullopt;
    std::vector<netaddr> randomize_prefix;

    std::string mac_source;
    std::string mac_dest;

    bool mac_consistency = false;
    bool fix_checksums = false;
    bool verbose = false;
    bool pcap_preload = false;

    bool is_pcap_file() const {
        std::filesystem::path p(source);
        return p.extension() == ".pcap" || p.extension() == ".pcapng";
    }

    bool has_rate_limiter() const {
        return pkt_rate != std::numeric_limits<size_t>::max();
    }

    bool has_speed_control() const {
        return speed > 0;
    }

    bool has_randomizer() const {
        return randomize_src_ip || randomize_dst_ip || !randomize_prefix.empty();
    }
};

struct generator_stats
{
    std::atomic_size_t packets = 0;
    std::atomic_size_t bytes   = 0;
    std::atomic_size_t errors  = 0;
    std::atomic_size_t discarded = 0;
};

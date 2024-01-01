#pragma once
#include <pcap/pcap.h>

#include <memory>
#include <cstdint>
#include <string>
#include <optional>
#include <map>
#include <iostream>

struct packet
{
    pcap_pkthdr hdr_;
    std::shared_ptr<uint8_t[]> data_;
    std::size_t len_;

    template <std::size_t N>
    static inline auto from_hex_stream(const char (&str)[N]) -> packet {
        auto pkt = std::make_shared<uint8_t[]>(N/2);
        for (std::size_t i = 0; i < N/2; ++i) {
            pkt[i] = std::stoi(std::string(str + i*2, 2), nullptr, 16);
        }
        return { .hdr_ = {}, .data_ = pkt, .len_ = N/2 };
    }

    template <std::size_t N>
    static inline auto from_c_string(const char (&str)[N]) -> packet {
        auto pkt = std::make_shared<uint8_t[]>(N);
        memcpy(pkt.get(), str, N);
        return { .hdr_ ={}, .data_ = pkt, .len_ = N };
    }

    static inline auto from_pcap(const char *pcap_file) -> std::vector<packet> {
        char errbuf[PCAP_ERRBUF_SIZE];
        std::cerr << "preloading " << pcap_file << "..." << std::endl;
        auto pcap = ::pcap_open_offline(pcap_file, errbuf);
        if (!pcap) {
            throw std::runtime_error("pcap_open_offline: " + std::string(errbuf));
        }

        std::vector<packet> packets;
        packets.reserve(65536);

        struct pcap_pkthdr *hdr;
        const uint8_t *data;
        while (int ret = ::pcap_next_ex(pcap, &hdr, &data)) {
            if (ret == -1) {
                throw std::runtime_error("pcap_next_ex: " + std::string(pcap_geterr(pcap)));
            }
            if (ret == -2) {
                break;
            }
            packets.push_back({ .hdr_ = *hdr, .data_ = make_buf(const_cast<uint8_t*>(data), hdr->len), .len_ = hdr->len});
        }

        ::pcap_close(pcap);
        std::cerr << "preload done." << std::endl;
        return packets;
    }

    static auto builder(const std::string &name, std::optional<uint16_t> len) -> packet
    {
        auto it = catalog_.find(name);
        if (it == catalog_.end()) {
            throw std::runtime_error("packet '" + name + "' not found!");
        }

        return it->second(len);
    }

    void resize(uint16_t size) {
        if (size < len_) {
            len_ = size;
        } else {
            auto new_data = std::make_shared<uint8_t[]>(size);
            memcpy(new_data.get(), data_.get(), len_);
            bzero(new_data.get() + len_, size - len_);
            data_ = new_data;
            len_ = size;
        }
    }

    private:
        static inline auto make_buf(uint8_t *data, size_t len) -> std::shared_ptr<uint8_t[]> {
            auto buf = std::make_shared<uint8_t[]>(len);
            memcpy(buf.get(), data, len);
            return buf;
        }

        static std::map<std::string, std::function<packet(std::optional<uint16_t>)>> catalog_;
};

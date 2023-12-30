#pragma once

#include <memory>
#include <cstdint>
#include <string>
#include <optional>
#include <map>

struct packet
{
    std::shared_ptr<uint8_t[]> data_;
    std::size_t len_;

    template <std::size_t N>
    static inline auto from_hex_stream(const char (&str)[N]) -> packet {
        auto pkt = std::make_shared<uint8_t[]>(N/2);
        for (std::size_t i = 0; i < N/2; ++i) {
            pkt[i] = std::stoi(std::string(str + i*2, 2), nullptr, 16);
        }
        return { .data_ = pkt, .len_ = N/2 };
    }

    template <std::size_t N>
    static inline auto from_c_string(const char (&str)[N]) -> packet {
        auto pkt = std::make_shared<uint8_t[]>(N);
        memcpy(pkt.get(), str, N);
        return { .data_ = pkt, .len_ = N };
    }

    static auto builder(const std::string &name, std::optional<uint16_t> len) -> packet
    {
        auto it = catalog_.find(name);
        if (it == catalog_.end()) {
            throw std::runtime_error("packet '" + name + "'not found!");
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
        static std::map<std::string, std::function<packet(std::optional<uint16_t>)>> catalog_;

};

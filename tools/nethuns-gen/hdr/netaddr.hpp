#pragma once

#include <nethuns/nethuns.h>

#include <string>

struct netaddr
{
    uint32_t addr = 0;
    uint32_t mask = 0;

    netaddr(const char *str) {
        auto pos = std::string{str}.find('/');
        if (pos == std::string::npos) {
            throw std::runtime_error("invalid prefix");
        }
        auto addr_str = std::string{str}.substr(0, pos);
        auto prefix_str = std::string{str}.substr(pos + 1);

        mask = htonl(~((1ul << (32 - std::stoi(prefix_str))) - 1));
        addr = inet_addr(addr_str.c_str()) & mask;
    }

    auto to_string() const -> std::string {
        char addr_buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr, addr_buf, INET_ADDRSTRLEN);

        char mask_buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &mask, mask_buf, INET_ADDRSTRLEN);

        return std::string{addr_buf} + "/" + std::string{mask_buf};
    }
};

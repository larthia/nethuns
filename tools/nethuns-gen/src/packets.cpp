#include <cstdint>
#include <map>
#include <string>
#include <functional>

#include "hdr/packet.hpp"

// build a packet from a hex stream

std::map<std::string, std::function<std::vector<packet>(std::optional<uint16_t>)>> packet::catalog_ = {
    {"tcp:syn", [] (std::optional<uint16_t>) -> std::vector<packet> {
            return { packet::from_hex_stream("20e52a9f5fcaa41f72a69c1b080045000034114640008006317e0a011977174c7d3cc0bb0050189ad2860000000080022000eae30000020405b40103030801010402") };
        }
    }
};

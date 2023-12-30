#pragma  once
#include <vector>

#include "hdr/generator.hpp"

struct options {
    std::vector<generator> generators;
};

constexpr unsigned int bitfield(bool first) {
    return (first ? 1u : 0u);
}

template <typename ...Bools>
constexpr unsigned int bitfield(bool first, Bools... rest) {
    return (first ? 1u : 0u) | bitfield(rest...) << 1;
}

void validate_options(const options& opt);

options
parse_opt(int argc, char **argv);

int
run(const options& opt);
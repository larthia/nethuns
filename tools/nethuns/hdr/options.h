#pragma once
#include <nethuns/nethuns.h>

#include <stdint.h>

struct options {
    const char *dev;
    int queue;
    uint64_t count;
    bool verbose;
    bool meter;
    struct nethuns_socket_options sopt;
};

extern struct options parse_opt(int argc, char *argv[]);

extern void validate_options(const struct options *opt);

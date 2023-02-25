#pragma once
#include <nethuns/nethuns.h>

struct options {
    const char *dev;
    int queue;
    bool verbose;
    bool meter;
    struct nethuns_socket_options sopt;
};

extern struct options parse_opt(int argc, char *argv[]);

extern void validate_options(const struct options *opt);
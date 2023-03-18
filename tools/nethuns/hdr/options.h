#pragma once
#include <nethuns/nethuns.h>

#include <stdint.h>

#define MAX_DEVICES     128

struct dev_queue {
    const char *name;
    int queue;
};

struct options {
    struct dev_queue dev[MAX_DEVICES];
    int num_devs;
    uint64_t count;
    bool verbose;
    int meter;
    struct nethuns_socket_options sopt;
};

extern struct options parse_opt(int argc, char *argv[]);

extern void validate_options(const struct options *opt);

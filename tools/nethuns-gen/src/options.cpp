#include "hdr/options.hpp"
#include "hdr/generator.hpp"
#include <arpa/inet.h>
#include <iostream>
#include <vector>
#include <getopt.h>

void help(const char *progname) {
    std::cout << "Usage: " << progname << " [options]" << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  -G\t\t\t\tadd a generator" << std::endl;
    std::cout << "  -c <cpu>\t\t\tset cpu to run on" << std::endl;
    std::cout << "  -I <dev>\t\t\tset device to send packets on" << std::endl;
    std::cout << "  -S <source>\t\t\tset the source of packets (e.g. template name or pcap)" << std::endl;
    std::cout << "  -R <mac_source>\t\tset source mac address" << std::endl;
    std::cout << "  -D <mac_dest>\t\t\tset destination mac address" << std::endl;
    std::cout << "  -m <max_packets>\t\tset maximum number of packets to send" << std::endl;
    std::cout << "  -r <pkt_rate>\t\t\tset packet rate" << std::endl;
    std::cout << "  -l <loops>\t\t\tset number of loops" << std::endl;
    std::cout << "  -L <pktlen>\t\t\tset packet length" << std::endl;
    std::cout << "  -p <randomize_prefix>\t\trandomize by prefix" << std::endl;
    std::cout << "  -a <amp>\t\t\tset amplitude" << std::endl;
    std::cout << "  -X <seed>\t\t\tset the random seed for then generator" << std::endl;
    std::cout << "  -x\t\t\t\tfix checksums" << std::endl;
    std::cout << "  -P\t\t\t\tpreload pcap files" << std::endl;
    std::cout << "  -v\t\t\t\tverbose" << std::endl;
    std::cout << "  -y <speed>\t\t\tset speed (for pcap, 0 means top-speed)" << std::endl;
    std::cout << "  -h\t\t\t\tshow this help" << std::endl;
}

template <typename T>
auto deref(T *ptr) -> T& {
    if (ptr == nullptr) {
        throw std::runtime_error("no generator to set option for");
    }
    return *ptr;
}


options
parse_opt(int argc, char **argv)
{
    options opt;
    generator *gen = nullptr;

    uint32_t gen_id = 0;

    int c;
    while ((c = getopt(argc, argv, "GS:I:R:D:c:m:r:L:l:s:d:p:a:y:X:Pxvh")) != -1) {
        switch (c) {
            case 'G':
                opt.generators.emplace_back();
                gen = &opt.generators.back();
                gen->id = gen_id++;
                gen->seed = gen->id;
                break;
            case 'X':
                deref(gen).seed = std::stoi(optarg);
                break;
            case 'c':
                deref(gen).cpu = std::stoi(optarg);
                break;
            case 'I':
                deref(gen).dev = std::string{optarg};
                break;
            case 'S':
                deref(gen).source = std::string{optarg};
                break;
            case 'R':
                deref(gen).mac_source = std::string{optarg};
                break;
            case 'D':
                deref(gen).mac_dest = std::string{optarg};
                break;
            case 'm':
                deref(gen).max_packets = std::stoul(optarg);
                break;
            case 'r':
                deref(gen).pkt_rate = std::stoul(optarg);
                break;
            case 'l':
                deref(gen).loops = std::stoul(optarg);
                break;
            case 'L':
                deref(gen).pktlen = std::stoi(optarg);
                break;
            case 'p':
                deref(gen).randomize_prefix.push_back(netaddr(optarg));
                break;
            case 'a':
                deref(gen).amp = std::stoi(optarg);
                break;
            case 'x':
                deref(gen).fix_checksums = true;
                break;
            case 'P':
                deref(gen).pcap_preload = true;
                break;
            case 'v':
                deref(gen).verbose = true;
                break;
            case 'y':
                deref(gen).speed = std::stoi(optarg);
                break;
            case 'h':
                help(argv[0]);
                exit(0);
            default:
                help(argv[0]);
                exit(1);
        }
    }

    return opt;
}

void validate_options(const options &opt) {
    if (opt.generators.empty()) {
        throw std::runtime_error("no generators specified");
    }

    for (auto &gen : opt.generators) {
        if (gen.source.empty()) {
            throw std::runtime_error("no source specified");
        }
    }
}
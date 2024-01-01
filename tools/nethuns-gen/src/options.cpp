#include "hdr/options.hpp"
#include "hdr/generator.hpp"
#include <arpa/inet.h>
#include <iostream>
#include <vector>
#include <getopt.h>

void help(const char *progname) {
    std::cout << "Usage: " << progname << " [options]" << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  -G\t\t\tadd a generator" << std::endl;
    std::cout << "  -c <cpu>\t\tset the cpu affinity" << std::endl;
    std::cout << "  -I <interface>\tset the interface to use" << std::endl;
    std::cout << "  -S <source>\t\tset the source of the packets" << std::endl;
    std::cout << "  -R <mac>\t\tset the source mac address" << std::endl;
    std::cout << "  -D <mac>\t\tset the destination mac address" << std::endl;
    std::cout << "  -z\t\t\tcheck mac consistency" << std::endl;
    std::cout << "  -m <packets>\t\tset the number of packets to send" << std::endl;
    std::cout << "  -r <pps>\t\tset the packet rate" << std::endl;
    std::cout << "  -b <bps>\t\tset the bit rate" << std::endl;
    std::cout << "  -l <loops>\t\tset the number of loops" << std::endl;
    std::cout << "  -L <length>\t\tset the packet length" << std::endl;
    std::cout << "  -s <prefix>\t\trandomize the source ip address" << std::endl;
    std::cout << "  -d <prefix>\t\trandomize the destination ip address" << std::endl;
    std::cout << "  -p <prefix>\t\trandomize prefix" << std::endl;
    std::cout << "  -a <amplification>\tset the amplification factor" << std::endl;
    std::cout << "  -x\t\t\tfix checksums" << std::endl;
    std::cout << "  -v\t\t\tverbose" << std::endl;
    std::cout << "  -h\t\t\tshow this help" << std::endl;
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

    int c;
    while ((c = getopt(argc, argv, "GS:I:R:D:c:m:r:L:l:s:d:p:a:y:Pxzvh")) != -1) {
        switch (c) {
            case 'G':
                opt.generators.emplace_back();
                gen = &opt.generators.back();
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
            case 'z':
                deref(gen).mac_consistency = true;
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
            case 's':
                deref(gen).randomize_src_ip = netaddr(optarg);
                break;
            case 'd':
                deref(gen).randomize_dst_ip = netaddr(optarg);
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
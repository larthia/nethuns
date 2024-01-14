#include "hdr/options.hpp"
#include "hdr/generator.hpp"
#include <arpa/inet.h>
#include <iostream>
#include <vector>
#include <getopt.h>

void help(const char *progname) {
    std::cout << "Usage: " << progname << " [OPTIONS]" << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  -G, --generator\t\t\tadd a generator" << std::endl;
    std::cout << "  -c, --cpu <INT>\t\t\tset cpu to run on" << std::endl;
    std::cout << "  -I, --interface <DEV>\t\t\tset device to send packets on" << std::endl;
    std::cout << "  -S, --source <STRING>\t\t\tset the source of packets (e.g. template name or pcap)" << std::endl;
    std::cout << "  -s, --mac_source <STRING>\t\tset source mac address" << std::endl;
    std::cout << "  -d, --mac_dest <STRING>\t\tset destination mac address" << std::endl;
    std::cout << "  -m, --max_packets <INT>\t\tset maximum number of packets to send" << std::endl;
    std::cout << "  -r, --pkt_rate <INT>\t\t\tset packet rate" << std::endl;
    std::cout << "  -l, --loops <INT>\t\t\tset number of loops" << std::endl;
    std::cout << "  -L, --pktlen <INT>\t\t\tset packet length" << std::endl;
    std::cout << "  -R, --randomize <STRING>\t\trandomize flows by addr/prefix (e.g. 192.168.0.0/24)" << std::endl;
    std::cout << "  -a, --amplitude <INT>\t\t\tset amplitude" << std::endl;
    std::cout << "  -y, --speed <INT>\t\t\tset speed (for pcap, 0 means top-speed)" << std::endl;
    std::cout << "  -X, --seed <INT>\t\t\tset the random seed for then generator" << std::endl;
    std::cout << "  -x, --fix_checksums\t\t\tfix checksums" << std::endl;
    std::cout << "  -P, --preload\t\t\t\tpreload pcap files" << std::endl;
    std::cout << "  -v, --verbose\t\t\t\tverbose" << std::endl;
    std::cout << "  -h, --help\t\t\t\tshow this help" << std::endl;
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

   struct option long_options[] = {
        {"generator", no_argument, 0, 'G'},
        {"cpu", required_argument, 0, 'c'},
        {"interface", required_argument, 0, 'I'},
        {"source", required_argument, 0, 'S'},
        {"mac_source", required_argument, 0, 's'},
        {"mac_dest", required_argument, 0, 'd'},
        {"max_packets", required_argument, 0, 'm'},
        {"pkt_rate", required_argument, 0, 'r'},
        {"loops", required_argument, 0, 'l'},
        {"pktlen", required_argument, 0, 'L'},
        {"randomize", required_argument, 0, 'R'},
        {"amplitude", required_argument, 0, 'a'},
        {"speed", required_argument, 0, 'y'},
        {"seed", required_argument, 0, 'X'},
        {"fix_checksums", no_argument, 0, 'x'},
        {"preload", no_argument, 0, 'P'},
        {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };


    int c;
    int option_index = 0;
    while ((c = getopt_long(argc, argv, "Gc:I:S:s:d:m:r:l:L:R:a:y:X:xPvh", long_options, &option_index)) != -1) {
        switch (c) {
            case 'G':
                opt.generators.emplace_back();
                gen = &opt.generators.back();
                gen->id = gen_id++;
                gen->seed = gen->id;
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
            case 's':
                deref(gen).mac_source = std::string{optarg};
                break;
            case 'd':
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
            case 'R':
                deref(gen).randomize_prefix.push_back(netaddr(optarg));
                break;
            case 'a':
                deref(gen).amp = std::stoi(optarg);
                break;
            case 'y':
                deref(gen).speed = std::stoi(optarg);
                break;
            case 'X':
                deref(gen).seed = std::stoi(optarg);
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
            throw std::runtime_error("no generator source specified");
        }
    }
}
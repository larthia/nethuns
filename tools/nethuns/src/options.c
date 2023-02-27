#include "hdr/options.h"

#include <getopt.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>

#include <nethuns/nethuns.h>

static const char *version = "0.1";

void help(const char* progname) {
    fprintf(stdout,
            "Usage: %s [-b num_blocks] [-r num_packets] [-s packet_size] [-t timeout_ms]\n"
            "           [-Q direction] [-C capture_mode] [-M socket_mode] [-p] [-x] [-i device]\n"
            "           [-q queue] [-c count] [-v] [-P xdp_prog] [-S xdp_prog_sec] [-K xsk_map_name]\n"
            "           [-d pin_dir] [-R] [-Y] [-V] [-h]\n"
            "\n"
            "Options:\n"
            "  -b num_blocks     Number of blocks to allocate\n"
            "  -r num_packets    Number of packets to receive\n"
            "  -s packet_size    Size of each packet in bytes\n"
            "  -t timeout_ms     Timeout for each receive call in milliseconds\n"
            "  -Q direction      Direction of packets to capture (in/out/inout)\n"
            "  -C capture_mode   Capture mode (default/skb/drv/zerocopy)\n"
            "  -M socket_mode    Socket mode (rx_tx/rx/tx)\n"
            "  -p                Disable promiscuous mode\n"
            "  -x                Enable bypass of the tx queue discipline\n"
            "  -i device         Name of the device to capture packets from\n"
            "  -q queue          Queue ID to capture packets from (default -1)\n"
            "  -c count          Exit after capturing count packets\n"
            "  -v                Enable verbose output\n"
#if NETHUNS_SOCKET == NETHUNS_SOCKET_XDP
            "  -P xdp_prog       Name of the XDP program to load\n"
            "  -S xdp_prog_sec   Name of the XDP program section to load\n"
            "  -K xsk_map_name   Name of the XDP shared memory map\n"
            "  -d pin_dir        Directory to pin XDP program and maps in\n"
            "  -R                Reuse existing maps when loading XDP program\n"
#endif
            "  -Y                Run meter, don't print packets\n"
            "  -V                Print version information and exit\n"
            "  -h                Print this help message and exit\n",
            progname);
    exit(EXIT_SUCCESS);
}

struct options
parse_opt(int argc, char *argv[]) {
    struct options ret = {
        .dev = NULL,
        .queue = NETHUNS_ANY_QUEUE,
        .count = UINT64_MAX,
        .meter = false,
        .sopt = {
                    .numblocks       = 1
                ,   .numpackets      = 4096
                ,   .packetsize      = 2048
                ,   .timeout_ms      = 0
                ,   .dir             = nethuns_in_out
                ,   .capture         = nethuns_cap_default
                ,   .mode            = nethuns_socket_rx_tx
                ,   .timestamp       = true
                ,   .promisc         = true
                ,   .rxhash          = true
                ,   .tx_qdisc_bypass = false
                ,   .xdp_prog        = NULL
                ,   .xdp_prog_sec    = NULL
                ,   .xsk_map_name    = NULL
                ,   .reuse_maps      = false
                ,   .pin_dir         = NULL
                }
    };

    int c;
#if NETHUNS_SOCKET == NETHUNS_SOCKET_XDP
    while ((c = getopt(argc, argv, "b:r:s:t:Q:C:M:i:pvq:c:P:S:K:d:RYh?V")) != -1)
#else
    while ((c = getopt(argc, argv, "b:r:s:t:Q:C:M:i:pvq:c:Yh?V")) != -1)
#endif
    {
        switch (c)
        {
        case 'b':
            ret.sopt.numblocks = atoi(optarg);
            break;
        case 'r':
            ret.sopt.numpackets = atoi(optarg);
            break;
        case 's':
            ret.sopt.packetsize = atoi(optarg);
            break;
        case 't':
            ret.sopt.timeout_ms = atoi(optarg);
            break;
        case 'Q':
            if (strcmp(optarg, "in") == 0)
                ret.sopt.dir = nethuns_in;
            else if (strcmp(optarg, "out") == 0)
                ret.sopt.dir = nethuns_out;
            else if (strcmp(optarg, "inout") == 0)
                ret.sopt.dir = nethuns_in_out;
            else {
                fprintf(stderr, "invalid direction: %s\n", optarg);
                exit(EXIT_FAILURE);
            }
            break;
        case 'C':
            if (strcmp(optarg, "default") == 0)
                ret.sopt.capture = nethuns_cap_default;
            else if (strcmp(optarg, "skb") == 0)
                ret.sopt.capture = nethuns_cap_skb_mode;
            else if (strcmp(optarg, "drv") == 0)
                ret.sopt.capture = nethuns_cap_drv_mode;
            else if (strcmp(optarg, "zerocopy") == 0)
                ret.sopt.capture = nethuns_cap_zero_copy;
            else {
                fprintf(stderr, "invalid capture mode: %s\n", optarg);
                exit(EXIT_FAILURE);
            }
            break;
        case 'M':
            if (strcmp(optarg, "rx_tx") == 0)
                ret.sopt.mode = nethuns_socket_rx_tx;
            else if (strcmp(optarg, "rx") == 0)
                ret.sopt.mode = nethuns_socket_rx_only;
            else if (strcmp(optarg, "tx") == 0)
                ret.sopt.mode = nethuns_socket_tx_only;
            else {
                fprintf(stderr, "invalid socket mode: %s\n", optarg);
                exit(EXIT_FAILURE);
            }
            break;
        case 'p':
            ret.sopt.promisc = false;
            break;
        case 'x':
            ret.sopt.tx_qdisc_bypass = true;
            break;
        case 'i':
            ret.dev = optarg;
            break;
        case 'q':
            ret.queue = atoi(optarg);
            break;
        case 'c':
            ret.count = atoi(optarg);
            break;
        case 'v':
            ret.verbose = true;
            break;
#if NETHUNS_SOCKET == NETHUNS_SOCKET_XDP
        case 'P':
            ret.sopt.xdp_prog = optarg;
            break;
        case 'S':
            ret.sopt.xdp_prog_sec = optarg;
            break;
        case 'K':
            ret.sopt.xsk_map_name = optarg;
            break;
        case 'd':
            ret.sopt.pin_dir = optarg;
            break;
        case 'R':
            ret.sopt.reuse_maps = true;
            break;
#endif
        case 'Y':
            ret.meter = true;
            break;
        case 'V':
            fprintf(stderr, "version: %s, %s\n", version, nethuns_version());
            exit(EXIT_SUCCESS);
        case 'h':
	    __attribute__ ((fallthrough));
        case '?':
            help("nethuns-dump");
	    break;
        default:
            fprintf(stderr, "invalid option: %c", c);
            exit(EXIT_FAILURE);
        }
    }

    return ret;
}


void
validate_options(const struct options *opt)
{
    if (!opt->dev)
    {
        fprintf(stderr, "no device specified\n");
        exit(EXIT_FAILURE);
    }
}

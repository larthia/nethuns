#include <nethuns/nethuns.h>
#include <stdio.h>
#include <getopt.h>
#include <signal.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <thread>
#include <chrono>
#include <iostream>
#include <string>
#include <vector>


/// manage command line options
const struct option long_opts[] = {
        {"help", no_argument, 0, 'h'},
        {"interface", required_argument, 0, 'i'},
        {"sockets", required_argument, 0, 'n'},
        {"multithreading", no_argument, 0, 'm'},
        {"sockstats", required_argument, 0, 's'},
        {"debug", no_argument, 0, 'd'},
        {0, 0, 0, 0}
};

const std::string help_brief = "Usage:  nethuns-meter [ options ]\n" \
                                "Use --help (or -h) to see full option list and a complete description.\n\n"
                                "Required options: \n" \
                                "\t\t\t[ -i <ifname> ] \t set network interface \n" \
                                "Other options: \n" \
                                "\t\t\t[ -n <nsock> ] \t\t set number of sockets \n" \
                                "\t\t\t[ -m ] \t\t\t enable multithreading \n" \
                                "\t\t\t[ -s <sockid> ] \t enable per socket stats \n" \
                                "\t\t\t[ -d ] \t\t\t enable extra debug printing \n";

const std::string help_long = "Usage:  nethuns-meter [ options ] \n\n" \
                                "-h, --help \t\t\t\t Show program usage and exit.\n\n" \
                                "Required options: \n\n" \
                                "-i, --interface \t<ifname> \t Name of the network interface that nethuns-meter operates on.\n\n" \
                                "Other options: \n\n" \
                                "-n, --sockets \t\t<nsock> \t Number of sockets to use. By default, only one socket is used.\n\n" \
                                "-m, --multithreading \t\t\t Enable multithreading. By default, only one thread is used. " \
                                "\n\t\t\t\t\t If multithreading is enabled, and there is more than one socket in use, " \
                                "\n\t\t\t\t\t each socket is handled by a separated thread.\n\n" \
                                "-s, --sockstats \t<sockid> \t Enable printing of complete statistics for the <sockid> socket in range [0, nsock). " \
                                "\n\t\t\t\t\t By default, aggregated statistics for all the sockets in use are printed out.\n\n" \
                                "-d, --debug \t\t\t\t Enable printing of extra info out to stdout for debug purposes " \
                                "\n\t\t\t\t\t (e.g., IP address fields of received packets).\n\n";

// write source and destination IP addresses from packet data out to stdout (debug purposes)
std::string print_addrs(const unsigned char* frame)
{
    // 802.1Q header structure.
    struct vlan_ethhdr {
        u_char h_dest[ETHER_ADDR_LEN];
        u_char h_source[ETHER_ADDR_LEN];
        u_int16_t h_vlan_proto;
        u_int16_t h_vlan_TCI;
        u_int16_t h_vlan_encapsulated_proto;
    };

    uint32_t ipsrc, ipdst;
    char ipsrc_buf[16], ipdst_buf[16];

    // access ethernet header
    const struct ether_header* e_hdr = reinterpret_cast<const struct ether_header*>(frame);
    if (e_hdr == nullptr)
        throw std::runtime_error("Error: ETH header parsing");

    // check presence of vlan header
    const struct vlan_ethhdr *vlan_hdr = nullptr;
    if (e_hdr->ether_type == htons(ETHERTYPE_VLAN))
        vlan_hdr = reinterpret_cast<const struct vlan_ethhdr*>(frame);

    // access IP header
    const struct ip* ip_hdr = (vlan_hdr) ?
                              reinterpret_cast<const struct ip*>(vlan_hdr + 1) :
                              reinterpret_cast<const struct ip*> (e_hdr + 1);
    if (ip_hdr == nullptr)
        throw std::runtime_error("Error: IP header parsing");

    ipsrc = reinterpret_cast<uint32_t>(ip_hdr->ip_src.s_addr);      // IP src (binary format)
    ipdst = reinterpret_cast<uint32_t>(ip_hdr->ip_dst.s_addr);      // IP dst (binary format)

    inet_ntop(AF_INET, reinterpret_cast<const void *>(&ipsrc), ipsrc_buf, sizeof(ipsrc_buf));  // convert IPv4 address from binary to text form
    inet_ntop(AF_INET, reinterpret_cast<const void *>(&ipdst), ipdst_buf, sizeof(ipdst_buf));  // convert IPv4 address from binary to text form

    return "IP, " + std::string(ipsrc_buf) + " > " + std::string(ipdst_buf);
}


nethuns_socket_t **out;
struct nethuns_socket_options netopt;
char (*errbufs)[NETHUNS_ERRBUF_SIZE];

std::string interface = "";
int nsock = 1;
bool mthreading = false;
std::vector<std::thread> threads;
bool sockstats = false;
bool debug = false;

// terminate application
volatile bool term = false;

// termination signal handler
void terminate(int exit_signal)
{
    (void)exit_signal;
    term = true;
}

// compute stats
std::vector<long> totals;

// aggregated stats
void global_meter()
{
    auto now = std::chrono::system_clock::now();
    long old_totals = 0;
    while (!term) {
        now += std::chrono::seconds(1);
        std::this_thread::sleep_until(now);
        long x = 0;
        for (auto &total : totals) {
            x += total;
        }
    	std::cout << "pkt/sec: " << x - old_totals << std::endl;
        old_totals = x;
    }
}

// aggregated stats and per-socket detailed stats
void sock_meter(int sock_idx)
{
    auto now = std::chrono::system_clock::now();
    long old_totals = 0;
    while (!term) {
        now += std::chrono::seconds(1);
        std::this_thread::sleep_until(now);
        long x = 0;
        for (auto &total : totals) {
            x += total;
        }
	    nethuns_stat stats;
    	nethuns_stats(out[sock_idx], &stats);

    	std::cout << "pkt/sec: " << x - old_totals
                    << " { rx:" << stats.rx_packets
                    << " tx:" << stats.tx_packets
                    << " drop:" << stats.rx_dropped
                    << " ifdrop:" << stats.rx_if_dropped
                    << " rx_inv:" << stats.rx_invalid
                    << " tx_inv:" << stats.tx_invalid
                    << " freeze:" << stats.freeze
                    << " }" << std::endl;
        old_totals = x;
    }
}

// setup socket and rings
void setup_rx_ring(int th_idx)
{
    out[th_idx] = nethuns_open(&netopt, errbufs[th_idx]);
    if (!out[th_idx]) {
        throw std::runtime_error(errbufs[th_idx]);
    }

    if (nethuns_bind(out[th_idx], interface.c_str(), nsock > 1 ? th_idx : NETHUNS_ANY_QUEUE) < 0) {
        throw nethuns_exception(out[th_idx]);
    }

    if (debug) {
        std::cout << "Thread: " << th_idx
                << ", bind on " << interface
                << ":" << (nsock > 1 ? th_idx : NETHUNS_ANY_QUEUE)
                << std::endl;
    }
}

// receive and process a packet
void recv_pkt(int th_idx, uint64_t &count_to_dump)
{
    const nethuns_pkthdr_t *pkthdr = nullptr;
    const unsigned char *frame = nullptr;
    uint64_t pkt_id = nethuns_recv(out[th_idx], &pkthdr, &frame);

    if (pkt_id == NETHUNS_ERROR) {
        throw nethuns_exception(out[th_idx]);
    }

    if (pkt_id > 0) {
        // process valid packet here

        if (debug) {
            std::cout << "Thread: " << th_idx
                      << ", total: " << totals.at(th_idx)
                      << ", pkt: " << pkt_id << std::endl;
            std::cout << "Packet IP addr: " << print_addrs(frame) << std::endl;
        }

        totals.at(th_idx)++;

        count_to_dump++;
        if (count_to_dump == 10000000) {        // do something periodically
            count_to_dump = 0;
            nethuns_dump_rings(out[th_idx]);
        }

        nethuns_rx_release(out[th_idx], pkt_id);
    }
}

// single-thread single-socket reception
void st_recv(int th_idx)
{
    try {
        //setup_rx_ring(th_idx);

        uint64_t count_to_dump = 0;
        while (!term) {
            recv_pkt(th_idx, count_to_dump);
        }

        if (debug) {
            std::cout << "Thread: " << th_idx
                      << ", count to dump: " << count_to_dump
                      << std::endl;
        }
    } catch(nethuns_exception &e) {
        if (e.sock) {
            nethuns_close(e.sock);
        }
        std::cerr << e.what() << std::endl;
    } catch(std::exception &e) {
        std::cerr << e.what() << std::endl;
    }
}


int
main(int argc, char *argv[])
{
    int i, sock_idx = 0;

    // parse options from command line
    int opt = 0;
    int optidx = 0;
    opterr = 1;     // turn on/off getopt error messages
    if (argc > 1 && argc < 10) {
        while ((opt = getopt_long(argc, argv, "hi:n:ms:d", long_opts, &optidx)) != -1) {
            switch (opt) {
            case 'h':
                std::cout << help_long << std::endl;
                return 0;
            case 'i':
                if (optarg)
                    interface = optarg;
                break;
            case 'n':
                if (optarg)
                    nsock = atoi(optarg);
                break;
            case 'm':
                mthreading = true;
                break;
            case 's':
                sockstats = true;
                if (optarg)
                    sock_idx = atoi(optarg);
                break;
            case 'd':
                debug = true;
                break;
            default:
                std::cerr << "Error in parsing command line options.\n" << help_brief << std::endl;
                return 1;
            }
        }
    } else {
        std::cerr << help_brief << std::endl;
        return 1;
    }

    std::cout << "\nTest " << argv[0] << " started with parameters \n"
                            << "* interface: " << interface << " \n"
                            << "* sockets: " << nsock << " \n"
                            << "* multithreading: " << ((mthreading) ? " ON \n" : " OFF \n")
                            << "* sockstats: " << ((sockstats) ? (" ON  for socket " + std::to_string(sock_idx) + " \n")
                                                            : " OFF, aggregated stats only \n")
                            << "* debug: " << ((debug) ? " ON \n" : " OFF \n")
                            << std::endl;

    signal(SIGINT, terminate);  // register termination signal

    // nethuns options
    netopt =
    {
        .numblocks       = 1
    ,   .numpackets      = 4096
    ,   .packetsize      = 2048
    ,   .timeout_ms      = 0
    ,   .dir             = nethuns_in_out
    ,   .capture         = nethuns_cap_zero_copy
    ,   .mode            = nethuns_socket_rx_tx
    ,   .promisc         = true
    ,   .rxhash          = false
    ,   .tx_qdisc_bypass = true
    //,   .xdp_prog        = "/etc/nethuns/net_xdp.o"
    //,   .xdp_prog        = "/home/devel/xdp-tutorial/advanced03-AF_XDP/af_xdp_kern.o"
    //,   .xdp_prog_sec    = "xdp_sock1"
    ,   .xdp_prog        = nullptr
    ,   .xdp_prog_sec    = nullptr
    ,   .xsk_map_name    = nullptr
    ,   .reuse_maps      = false
    ,   .pin_dir         = nullptr
    };

    out = new nethuns_socket_t*[nsock]();
    errbufs = new char[nsock][NETHUNS_ERRBUF_SIZE]();       // one errbuf per thread

    for (i = 0; i < nsock; i++) {
        totals.push_back(0);        // stats counters init
    }

    // create thread for computing statistics
    if (!sockstats)
        std::thread(global_meter).detach();
    else
        std::thread(sock_meter, sock_idx).detach();

    // setup sockets and rings
    for (i = 0; i < nsock; i++) {
        setup_rx_ring(i);
    }

    // case single thread (main) with generic number of sockets
    if (!mthreading) {
        try {
            uint64_t count_to_dump = 0;
            while (!term) {
                for (i = 0; i < nsock; i++) {
                    recv_pkt(i, count_to_dump);
                }
            }

            if (debug) {
                std::cout << "Thread: MAIN, count to dump: "
                          << count_to_dump
                          << std::endl;
            }
        } catch(nethuns_exception &e) {
            if (e.sock) {
                nethuns_close(e.sock);
            }
            std::cerr << e.what() << std::endl;
            return 1;
        } catch(std::exception &e) {
            std::cerr << e.what() << std::endl;
            return 1;
        }
    } else {    // case multithreading enabled (num_threads == num_sockets)
        for (i = 0; i < nsock; i++) {
            std::thread th(st_recv, i);
            threads.push_back(std::move(th));
        }
    }

    for (i = 0; i < nsock; i++) {
        if (mthreading)
            threads.at(i).join();       // nsock recv_th threads to join
        nethuns_close(out[i]);          // nsock sockets to close
    }

    return 0;
}

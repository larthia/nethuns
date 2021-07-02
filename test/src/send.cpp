#include <nethuns/nethuns.h>
#include <stdio.h>
#include <getopt.h>
#include <signal.h>

#include <thread>
#include <chrono>
#include <iostream>
#include <string>
#include <vector>


/// manage command line options
const struct option long_opts[] = {
        {"help", no_argument, 0, 'h'},
        {"interface", required_argument, 0, 'i'},
        {"batch_size", required_argument, 0, 'b'},
        {"sockets", required_argument, 0, 'n'},
        {"multithreading", no_argument, 0, 'm'},
        {"zerocopy", no_argument, 0, 'z'},
        {0, 0, 0, 0}
};

const std::string help_brief = "Usage:  nethuns-send [ options ]\n" \
                                "Use --help (or -h) to see full option list and a complete description.\n\n"
                                "Required options: \n" \
                                "\t\t\t[ -i <ifname> ] \t set network interface \n" \
                                "Other options: \n" \
                                "\t\t\t[ -b <batch_sz> ] \t set batch size \n" \
                                "\t\t\t[ -n <nsock> ] \t\t set number of sockets \n" \
                                "\t\t\t[ -m ] \t\t\t enable multithreading \n" \
                                "\t\t\t[ -z ] \t\t\t enable send zero-copy \n";

const std::string help_long = "Usage:  nethuns-send [ options ] \n\n" \
                                "-h, --help \t\t\t\t Show program usage and exit.\n\n" \
                                "Required options: \n\n" \
                                "-i, --interface \t<ifname> \t Name of the network interface that nethuns-send operates on.\n\n" \
                                "Other options: \n\n" \
                                "-b, --batch_size \t<batch_sz> \t Batch size for packet transmission (default = 1).\n\n" \
                                "-n, --sockets \t\t<nsock> \t Number of sockets to use. By default, only one socket is used.\n\n" \
                                "-m, --multithreading \t\t\t Enable multithreading. By default, only one thread is used. " \
                                "\n\t\t\t\t\t If multithreading is enabled, and there is more than one socket in use, " \
                                "\n\t\t\t\t\t each socket is handled by a separated thread.\n\n" \
                                "-z, --zerocopy \t\t\t\t Enable send zero-copy. By default, classic send that requires a copy is used.\n";


nethuns_socket_t **out;
struct nethuns_socket_options netopt;
char (*errbufs)[NETHUNS_ERRBUF_SIZE];

uint64_t *pktid;
std::string interface = "";
int batch_size = 1;
int nsock = 1;
bool mthreading = false;
std::vector<std::thread> threads;
bool zerocopy = false;

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

void meter()
{
    auto now = std::chrono::system_clock::now();
    long old_totals = 0;
    while (!term) {
        now += std::chrono::seconds(1);
        std::this_thread::sleep_until(now);
        long x = 0;
        for (auto &total : totals)
            x += total;
        std::cout << "pkt/sec: " << x - old_totals << std::endl;
        old_totals = x;
    }
}

// setup and fill transmission ring
void fill_tx_ring(int th_idx, const unsigned char *payload, int pkt_size)
{
    unsigned int j;

    out[th_idx] = nethuns_open(&netopt, errbufs[th_idx]);
    if (!out[th_idx]) {
        throw std::runtime_error(errbufs[th_idx]);
    }

    if (nethuns_bind(out[th_idx], interface.c_str(), nsock > 1 ? th_idx : NETHUNS_ANY_QUEUE) < 0) {
        throw nethuns_exception(out[th_idx]);
    }

    // fill the slots in the tx ring (optimized send only)
    if (zerocopy) {
        for (j = 0; j < nethuns_txring_get_size(out[th_idx]); j++) {
            uint8_t *pkt = nethuns_get_buf_addr(out[th_idx], j);    // tell me where to copy the j-th packet to be transmitted
            memcpy(pkt, payload, pkt_size);                         // copy the packet
        }
        pktid[th_idx] = 0;                                          // first position (slot) in tx ring to be transmitted
    }
}

// transmit packets in the tx ring (use optimized send, zero copy)
void transmit_zc(int th_idx, int pkt_size)
{
    // prepare batch
    for (int n = 0; n < batch_size; n++) {
        if (nethuns_send_slot(out[th_idx], pktid[th_idx], pkt_size) <= 0)
            break;
        pktid[th_idx]++;
        totals.at(th_idx)++;
    }
    nethuns_flush(out[th_idx]);             // send batch
}

// transmit packets in the tx ring (use classic send, copy)
void transmit_c(int th_idx, const unsigned char *payload, int pkt_size)
{
    // prepare batch
    for (int n = 0; n < batch_size; n++) {
        if (nethuns_send(out[th_idx], payload, pkt_size) <= 0)
            break;
        totals.at(th_idx)++;
    }
    nethuns_flush(out[th_idx]);             // send batch
}

// single-thread single-socket transmission
void st_send(int th_idx, const unsigned char *payload, int pkt_size)
{
    try {
        fill_tx_ring(th_idx, payload, pkt_size);

        while (!term) {
            if (zerocopy)
                transmit_zc(th_idx, pkt_size);
            else
                transmit_c(th_idx, payload, pkt_size);
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
    int i;

    static const unsigned char payload[34] =
    {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf0, 0xbf, /* L`..UF.. */
        0x97, 0xe2, 0xff, 0xae, 0x08, 0x00, 0x45, 0x00, /* ......E. */
        0x00, 0x54, 0xb3, 0xf9, 0x40, 0x00, 0x40, 0x11, /* .T..@.@. */
        0xf5, 0x32, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, /* .2...... */
        0x07, 0x08
    };

    // parse options from command line
    int opt = 0;
    int optidx = 0;
    opterr = 1;     // turn on/off getopt error messages
    if (argc > 1 && argc < 10) {
        while ((opt = getopt_long(argc, argv, "hi:b:n:mz", long_opts, &optidx)) != -1) {
            switch (opt) {
            case 'h':
                std::cout << help_long << std::endl;
                return 0;
            case 'i':
                if (optarg)
                    interface = optarg;
                break;
            case 'b':
                if (optarg)
                    batch_size = atoi(optarg);
                break;
            case 'n':
                if (optarg)
                    nsock = atoi(optarg);
                break;
            case 'm':
                mthreading = true;
                break;
            case 'z':
                zerocopy = true;
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
                            << "* batch_size: " << batch_size << " \n"
                            << "* sockets: " << nsock << " \n"
                            << "* multithreading: " << ((mthreading) ? " ON \n" : " OFF \n")
                            << "* zero-copy: " << ((zerocopy) ? " ON \n" : " OFF \n")
                            << std::endl;

    signal(SIGINT, terminate);  // register termination signal

    // nethuns options
    netopt = {
        .numblocks       = 1
    ,   .numpackets      = 2048
    ,   .packetsize      = 2048
    ,   .timeout_ms      = 0
    ,   .dir             = nethuns_in_out
    ,   .capture         = nethuns_cap_zero_copy
    ,   .mode            = nethuns_socket_rx_tx
    ,   .promisc         = false
    ,   .rxhash          = false
    ,   .tx_qdisc_bypass = true
    ,   .xdp_prog        = nullptr
    ,   .xdp_prog_sec    = nullptr
    ,   .xsk_map_name    = nullptr
    ,   .reuse_maps      = false
    ,   .pin_dir         = nullptr
    };

    out = new nethuns_socket_t*[nsock]();
    pktid = new uint64_t[nsock]();                          // one packet index per socket (pos of next slot/packet to send in tx ring)
    errbufs = new char[nsock][NETHUNS_ERRBUF_SIZE]();       // one errbuf per thread

    for (i = 0; i < nsock; i++) {
        totals.push_back(0);        // stats counters init
    }

    // create thread for computing statistics
    std::thread stats_th(meter);

    // case single thread (main) with generic number of sockets
    if (!mthreading) {
        try {
            for (i = 0; i < nsock; i++) {
                fill_tx_ring(i, payload, 34);
            }

            while (!term) {
                for (i = 0; i < nsock; i++) {
                    if (zerocopy)
                        transmit_zc(i, 34);
                    else
                        transmit_c(i, payload, 34);
                }
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
            std::thread th(st_send, i, payload, 34);
            threads.push_back(std::move(th));
        }
    }

    for (i = 0; i < nsock; i++) {
        if (mthreading)
            threads.at(i).join();       // nsock send_th threads to join
        nethuns_close(out[i]);          // nsock sockets to close
    }
    stats_th.join();                    // 1 stats thread to join

    return 0;
}

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <unistd.h>
#include <signal.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

#include <chrono>
#include <iostream>
#include <atomic>
#include <thread>

#define BLOCK_SIZE		(1 << 22)
#define FRAME_SIZE		2048

#define NUM_BLOCKS		64
#define NUM_FRAMES		((BLOCK_SIZE * NUM_BLOCKS) / FRAME_SIZE)

#define BLOCK_RETIRE_TOV_IN_MS	64
#define BLOCK_PRIV_AREA_SZ	13

#define ALIGN_8(x)		(((x) + 8 - 1) & ~(8 - 1))

#define BLOCK_STATUS(x)		((x)->h1.block_status)
#define BLOCK_NUM_PKTS(x)	((x)->h1.num_pkts)
#define BLOCK_O2FP(x)		((x)->h1.offset_to_first_pkt)
#define BLOCK_LEN(x)		((x)->h1.blk_len)
#define BLOCK_SNUM(x)		((x)->h1.seq_num)
#define BLOCK_O2PRIV(x)		((x)->offset_to_priv)
#define BLOCK_PRIV(x)		((void *) ((uint8_t *) (x) + BLOCK_O2PRIV(x)))
#define BLOCK_HDR_LEN		(ALIGN_8(sizeof(struct block_desc)))
#define BLOCK_PLUS_PRIV(sz_pri)	(BLOCK_HDR_LEN + ALIGN_8((sz_pri)))

#ifndef likely
# define likely(x)		__builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
# define unlikely(x)		__builtin_expect(!!(x), 0)
#endif

struct block_desc {
	uint32_t version;
	uint32_t offset_to_priv;
	struct tpacket_hdr_v1 h1;
};

struct ring {
	struct iovec *rd;
	uint8_t *map;
	struct tpacket_req3 req;
};

static unsigned long packets_total = 0, bytes_total = 0;
static sig_atomic_t sigint = 0;

void sighandler(int num)
{
	sigint = 1;
}

static int setup_socket(struct ring *ring, char *netdev)
{
	int err, i, fd, v = TPACKET_V3;
	struct sockaddr_ll ll;

	fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (fd < 0) {
		perror("socket");
		exit(1);
	}

	err = setsockopt(fd, SOL_PACKET, PACKET_VERSION, &v, sizeof(v));
	if (err < 0) {
		perror("setsockopt");
		exit(1);
	}

	memset(&ring->req, 0, sizeof(ring->req));
	ring->req.tp_block_size = BLOCK_SIZE;
	ring->req.tp_frame_size = FRAME_SIZE;
	ring->req.tp_block_nr = NUM_BLOCKS;
	ring->req.tp_frame_nr = NUM_FRAMES;
	ring->req.tp_retire_blk_tov = BLOCK_RETIRE_TOV_IN_MS;
	ring->req.tp_sizeof_priv = BLOCK_PRIV_AREA_SZ;
	ring->req.tp_feature_req_word |= 0; // TP_FT_REQ_FILL_RXHASH;

	err = setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &ring->req,
			 sizeof(ring->req));
	if (err < 0) {
		perror("setsockopt");
		exit(1);
	}

	ring->map = (uint8_t *)mmap(NULL, ring->req.tp_block_size * ring->req.tp_block_nr,
			 PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED,
			 fd, 0);
	if (ring->map == MAP_FAILED) {
		perror("mmap");
		exit(1);
	}

	ring->rd = (iovec *)malloc(ring->req.tp_block_nr * sizeof(*ring->rd));
	assert(ring->rd);
	for (i = 0; i < ring->req.tp_block_nr; ++i) {
		ring->rd[i].iov_base = ring->map + (i * ring->req.tp_block_size);
		ring->rd[i].iov_len = ring->req.tp_block_size;
	}

	memset(&ll, 0, sizeof(ll));
	ll.sll_family = PF_PACKET;
	ll.sll_protocol = htons(ETH_P_ALL);
	ll.sll_ifindex = if_nametoindex(netdev);
	ll.sll_hatype = 0;
	ll.sll_pkttype = 0;
	ll.sll_halen = 0;

	err = bind(fd, (struct sockaddr *) &ll, sizeof(ll));
	if (err < 0) {
		perror("bind");
		exit(1);
	}

	return fd;
}

#ifdef __checked
static uint64_t prev_block_seq_num = 0;

void assert_block_seq_num(struct block_desc *pbd)
{
	if (unlikely(prev_block_seq_num + 1 != BLOCK_SNUM(pbd))) {
		printf("prev_block_seq_num:%"PRIu64", expected seq:%"PRIu64" != "
		       "actual seq:%"PRIu64"\n", prev_block_seq_num,
		       prev_block_seq_num + 1, (uint64_t) BLOCK_SNUM(pbd));
		exit(1);
	}

	prev_block_seq_num = BLOCK_SNUM(pbd);
}

static void assert_block_len(struct block_desc *pbd, uint32_t bytes, int block_num)
{
	if (BLOCK_NUM_PKTS(pbd)) {
		if (unlikely(bytes != BLOCK_LEN(pbd))) {
			printf("block:%u with %upackets, expected len:%u != actual len:%u\n",
			       block_num, BLOCK_NUM_PKTS(pbd), bytes, BLOCK_LEN(pbd));
			exit(1);
		}
	} else {
		if (unlikely(BLOCK_LEN(pbd) != BLOCK_PLUS_PRIV(BLOCK_PRIV_AREA_SZ))) {
			printf("block:%u, expected len:%lu != actual len:%u\n",
			       block_num, BLOCK_HDR_LEN, BLOCK_LEN(pbd));
			exit(1);
		}
	}
}

static void assert_block_header(struct block_desc *pbd, const int block_num)
{
	uint32_t block_status = BLOCK_STATUS(pbd);

	if (unlikely((block_status & TP_STATUS_USER) == 0)) {
		printf("block:%u, not in TP_STATUS_USER\n", block_num);
		exit(1);
	}

	assert_block_seq_num(pbd);
}
#else
static inline void assert_block_header(struct block_desc *pbd, const int block_num)
{
}
static void assert_block_len(struct block_desc *pbd, uint32_t bytes, int block_num)
{
}
#endif

static void display(struct tpacket3_hdr *ppd)
{
	struct ethhdr *eth = (struct ethhdr *) ((uint8_t *) ppd + ppd->tp_mac);
	struct iphdr *ip = (struct iphdr *) ((uint8_t *) eth + ETH_HLEN);

	if (eth->h_proto == htons(ETH_P_IP)) {
		struct sockaddr_in ss, sd;
		char sbuff[NI_MAXHOST], dbuff[NI_MAXHOST];

		memset(&ss, 0, sizeof(ss));
		ss.sin_family = PF_INET;
		ss.sin_addr.s_addr = ip->saddr;
		getnameinfo((struct sockaddr *) &ss, sizeof(ss),
			    sbuff, sizeof(sbuff), NULL, 0, NI_NUMERICHOST);

		memset(&sd, 0, sizeof(sd));
		sd.sin_family = PF_INET;
		sd.sin_addr.s_addr = ip->daddr;
		getnameinfo((struct sockaddr *) &sd, sizeof(sd),
			    dbuff, sizeof(dbuff), NULL, 0, NI_NUMERICHOST);

		printf("%s -> %s, ", sbuff, dbuff);
	}

	printf("rxhash: 0x%x\n", ppd->hv1.tp_rxhash);
}


std::atomic_long total_counter;

void meter()
{
    auto now = std::chrono::system_clock::now();
    for(;;)
    {
        now += std::chrono::seconds(1);
        std::this_thread::sleep_until(now);
        auto x = total_counter.exchange(0);
        std::cout << "pkt/sec: " << x << std::endl;
    }
}


static void walk_block(struct block_desc *pbd, const int block_num)
{
	int num_pkts = BLOCK_NUM_PKTS(pbd), i;
	unsigned long bytes = 0;
	unsigned long bytes_with_padding = BLOCK_PLUS_PRIV(BLOCK_PRIV_AREA_SZ);
	struct tpacket3_hdr *ppd;

	assert_block_header(pbd, block_num);

	ppd = (struct tpacket3_hdr *) ((uint8_t *) pbd + BLOCK_O2FP(pbd));


	for (i = 0; i < num_pkts /* BLOCK_SIZE/FRAME_SIZE */; ++i) {

        static uint64_t cntr = 0;
        if (cntr++ == 2000000)
        {
            cntr = 0;
            std::cerr << "num_pkts: " << num_pkts << std::endl;
        }

		bytes += ppd->tp_snaplen;
		if (ppd->tp_next_offset)
			bytes_with_padding += ppd->tp_next_offset;
		else
			bytes_with_padding += ALIGN_8(ppd->tp_snaplen + ppd->tp_mac);

        total_counter.fetch_add(1, std::memory_order_relaxed);

		// display(ppd);

		ppd = (struct tpacket3_hdr *) ((uint8_t *) ppd + ppd->tp_next_offset);
		__sync_synchronize();
	}

	assert_block_len(pbd, bytes_with_padding, block_num);

	packets_total += num_pkts;
	bytes_total += bytes;
}

void flush_block(struct block_desc *pbd)
{
	BLOCK_STATUS(pbd) = TP_STATUS_KERNEL;
	__sync_synchronize();
}

static void teardown_socket(struct ring *ring, int fd)
{
	munmap(ring->map, ring->req.tp_block_size * ring->req.tp_block_nr);
	free(ring->rd);
	close(fd);
}

int main(int argc, char **argp)
{
	int fd, err;
	socklen_t len;
	struct ring ring;
	struct pollfd pfd;
	unsigned int block_num = 0;
	struct block_desc *pbd;
	struct tpacket_stats_v3 stats;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s INTERFACE\n", argp[0]);
		return EXIT_FAILURE;
	}

    std::thread(meter).detach();

	signal(SIGINT, sighandler);

	memset(&ring, 0, sizeof(ring));
	fd = setup_socket(&ring, argp[argc - 1]);
	assert(fd > 0);

	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = fd;
	pfd.events = POLLIN | POLLERR;
	pfd.revents = 0;

	while (likely(!sigint)) {
		pbd = (struct block_desc *) ring.rd[block_num].iov_base;
retry_block:
		if ((BLOCK_STATUS(pbd) & TP_STATUS_USER) == 0) {
			poll(&pfd, 1, -1);
			goto retry_block;
		}

		walk_block(pbd, block_num);
		flush_block(pbd);
		block_num = (block_num + 1) % NUM_BLOCKS;
	}

	len = sizeof(stats);
	err = getsockopt(fd, SOL_PACKET, PACKET_STATISTICS, &stats, &len);
	if (err < 0) {
		perror("getsockopt");
		exit(1);
	}

	fflush(stdout);
	printf("\nReceived %u packets, %lu bytes, %u dropped, freeze_q_cnt: %u\n",
	       stats.tp_packets, bytes_total, stats.tp_drops,
	       stats.tp_freeze_q_cnt);

	teardown_socket(&ring, fd);
	return 0;
}


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

static void sighandler(int num)
{
	sigint = 1;
}

static int setup_socket(struct ring *ring, char *netdev)
{
	int err, i, fd, v = TPACKET_V3;
	struct sockaddr_ll ll;
	unsigned int blocksiz = 1 << 22, framesiz = 1 << 11;
	unsigned int blocknum = 64;

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
	ring->req.tp_block_size = blocksiz;
	ring->req.tp_frame_size = framesiz;
	ring->req.tp_block_nr = blocknum;
	ring->req.tp_frame_nr = (blocksiz * blocknum) / framesiz;
	ring->req.tp_retire_blk_tov = 60;
	ring->req.tp_feature_req_word = TP_FT_REQ_FILL_RXHASH;

	err = setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &ring->req,
			 sizeof(ring->req));
	if (err < 0) {
		perror("setsockopt");
		exit(1);
	}

	ring->map = mmap(NULL, ring->req.tp_block_size * ring->req.tp_block_nr,
			 PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED, fd, 0);
	if (ring->map == MAP_FAILED) {
		perror("mmap");
		exit(1);
	}

	ring->rd = malloc(ring->req.tp_block_nr * sizeof(*ring->rd));
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

static void walk_block(struct block_desc *pbd, const int block_num)
{
	int num_pkts = pbd->h1.num_pkts, i;
	unsigned long bytes = 0;
	struct tpacket3_hdr *ppd;

	ppd = (struct tpacket3_hdr *) ((uint8_t *) pbd +
				       pbd->h1.offset_to_first_pkt);
	for (i = 0; i < num_pkts; ++i) {
		bytes += ppd->tp_snaplen;
		display(ppd);

		ppd = (struct tpacket3_hdr *) ((uint8_t *) ppd +
					       ppd->tp_next_offset);
	}

	packets_total += num_pkts;
	bytes_total += bytes;
}

static void flush_block(struct block_desc *pbd)
{
	pbd->h1.block_status = TP_STATUS_KERNEL;
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
	unsigned int block_num = 0, blocks = 64;
	struct block_desc *pbd;
	struct tpacket_stats_v3 stats;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s INTERFACE\n", argp[0]);
		return EXIT_FAILURE;
	}

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

		if ((pbd->h1.block_status & TP_STATUS_USER) == 0) {
			poll(&pfd, 1, -1);
			continue;
		}

		walk_block(pbd, block_num);
		flush_block(pbd);
		block_num = (block_num + 1) % blocks;
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

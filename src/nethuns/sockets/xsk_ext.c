#define NETHUNS_SOCKET NETHUNS_SOCKET_XDP

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>

#include "nethuns/sockets/xdp.h"

#include "xdp/xsk.h"
#include "xdp/bpf.h"
#include "xdp/libbpf.h"

#include "xsk_ext.h"

#include "../api.h"

struct xsk_umem_info *
xsk_configure_umem(
	  struct nethuns_socket_xdp *sock
	, void *buffer
	, size_t size
	, size_t frame_size)
{
	struct xsk_umem_info *umem;
	struct xsk_umem_config cfg = {
		.fill_size = sock->base.rx_ring.mask + 1,
		.comp_size = sock->base.tx_ring.mask + 1,
		.frame_size = frame_size,
		.frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
		.flags = 0 // opt_umem_flags -> HUGEFPAGE?
	};

	int ret;

	printf("buffer %p size %ld (%lx) frame_size %ld (%lx)\n",
			buffer, size, size, frame_size, frame_size);

	umem = calloc(1, sizeof(*umem));
	if (!umem) {
        nethuns_perror(nethuns_socket(sock)->errbuf, "xsk_config_umem: could not allocate memory");
		return NULL;
    }

	ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq, &cfg);
	if (ret) {
        nethuns_perror(nethuns_socket(sock)->errbuf, "xsk_config_umem: could not create umem");
        return NULL;
    }

	umem->buffer = buffer;
	return umem;
}


//int
//xsk_populate_fill_ring(
//	  struct nethuns_socket_xdp *sock
//	, size_t frame_size)
//{
//	int ret, i;
//	uint32_t idx;
//
//	ret = xsk_ring_prod__reserve(&sock->umem->fq,
//				     XSK_RING_PROD__DEFAULT_NUM_DESCS, &idx);
//
//	if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS) {
//        	nethuns_perror(nethuns_socket(sock)->errbuf, "xsk_populate_fill_ring: could not reserve fill ring");
//		return -ret;
//	}
//
//	for (i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i++)
//		*xsk_ring_prod__fill_addr(&sock->umem->fq, idx++) =
//			i * frame_size;
//	xsk_ring_prod__submit(&sock->umem->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS);
//	return 0;
//}


struct xsk_socket_info *
xsk_configure_socket(struct nethuns_socket_xdp *sock)
{
	struct xsk_socket_config cfg;
	struct xsk_socket_info *xsk;
	int ret;
    unsigned int i;
    	unsigned int idx;

	xsk = calloc(1, sizeof(*xsk));
	if (!xsk)
		return NULL;

	xsk->umem = sock->umem;
	cfg.rx_size = sock->base.rx_ring.mask + 1;
	cfg.tx_size = sock->base.tx_ring.mask + 1;

	cfg.libbpf_flags = nethuns_socket(sock)->opt.xdp_prog != NULL
						? XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD
						: 0;

	cfg.xdp_flags = sock->xdp_flags;
	cfg.bind_flags = sock->xdp_bind_flags;

	ret = xsk_socket__create(&xsk->xsk, nethuns_socket(sock)->devname, nethuns_socket(sock)->queue, sock->umem->umem,
			sock->rx ? &xsk->rx : NULL,
			sock->tx ? &xsk->tx : NULL,
			&cfg);

	if (ret) {
        nethuns_perror(nethuns_socket(sock)->errbuf, "xsk_config: could not create socket");
		goto err;
	}

	ret = xsk_ring_prod__reserve(&xsk->umem->fq, cfg.rx_size, &idx);

	if (ret != cfg.rx_size) {
        nethuns_perror(nethuns_socket(sock)->errbuf, "xsk_config: could not reserve slots in fill ring");
		goto err;
	}

	for (i = 0; i < cfg.rx_size; i ++) {
		*xsk_ring_prod__fill_addr(&xsk->umem->fq, idx) = rx_frame(sock, idx);
		idx++;
	}

	xsk_ring_prod__submit(&xsk->umem->fq, cfg.rx_size);

	return xsk;
err:
	free(xsk);
	return NULL;
}

int
xsk_enter_into_map(struct nethuns_socket_xdp *sock)
{
	struct bpf_map *map;
	int xdp_map;

	map = bpf_object__find_map_by_name(sock->obj, "xsk_map");
	xdp_map = bpf_map__fd(map);
	if (xdp_map < 0) {
        nethuns_perror(nethuns_socket(sock)->errbuf, "xsk_enter_into_map: could find map: %s", strerror(xdp_map));
		return -1;
	}

	int fd = xsk_socket__fd(sock->xsk->xsk);
	int key, ret;

	key = 0;
	ret = bpf_map_update_elem(xdp_map, &key, &fd, 0);
	if (ret) {
        nethuns_perror(nethuns_socket(sock)->errbuf, "xsk_enter_into_map: bfp_map_update_elem");
		return -1;
	}

	return 0;
}

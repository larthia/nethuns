#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <src/xsk.h>

#include "xsk_ext.h"
#include <nethuns/priv/xdp.h>
#include <nethuns/nethuns.h>

struct xsk_umem_info *xsk_configure_umem(
	  struct nethuns_socket_xdp *sock
	, void *buffer
	, size_t size
	, size_t frame_size)
{
	struct xsk_umem_info *umem;
	struct xsk_umem_config cfg = {
		.fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
		.comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
		.frame_size = frame_size,
		.frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
		.flags = 0 // opt_umem_flags -> HUGEFPAGE?
	};

	int ret;

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


int xsk_populate_fill_ring(
	  struct nethuns_socket_xdp *sock
	, struct xsk_umem_info *umem
	, size_t frame_size)
{
	int ret, i;
	uint32_t idx;

	ret = xsk_ring_prod__reserve(&umem->fq,
				     XSK_RING_PROD__DEFAULT_NUM_DESCS, &idx);

	if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS) {
        nethuns_perror(nethuns_socket(sock)->errbuf, "xsk_populate_fill_ring: could not reserve for ring prod");
		return -ret;
	}

	for (i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i++)
		*xsk_ring_prod__fill_addr(&umem->fq, idx++) =
			i * frame_size;
	xsk_ring_prod__submit(&umem->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS);
	return 0;
}


struct xsk_socket_info *
xsk_configure_socket(
	  struct nethuns_socket_xdp *sock
	, struct xsk_umem_info *umem
	, uint32_t xdp_flags
	, uint32_t xdp_bind_flags
	, const char *dev
	, int ifindex 
	, int queue
	, uint32_t *prog_id
	, bool rx
	, bool tx)
{
	struct xsk_socket_config cfg;
	struct xsk_socket_info *xsk;
	struct xsk_ring_cons *rxr;
	struct xsk_ring_prod *txr;
	int ret;

	xsk = calloc(1, sizeof(*xsk));
	if (!xsk)
		return NULL;

	xsk->umem = umem;
	cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
	cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
	cfg.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD; 

	cfg.xdp_flags = xdp_flags;
	cfg.bind_flags = xdp_bind_flags;

	rxr = rx ? &xsk->rx : NULL;
	txr = tx ? &xsk->tx : NULL;

	ret = xsk_socket__create(&xsk->xsk, dev, queue, umem->umem,
				 rxr, txr, &cfg);
	if (ret) {
        nethuns_perror(nethuns_socket(sock)->errbuf, "xsk_config: could not create socket");
		return NULL;
	}

	ret = bpf_get_link_xdp_id(ifindex, prog_id, xdp_flags);
	if (ret) {
        nethuns_perror(nethuns_socket(sock)->errbuf, "xsk_config: could not link to xdp program");
		return NULL;
	}

	return xsk;
}

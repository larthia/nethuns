#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <src/xsk.h>

#include "xsk_ext.h"

struct xsk_umem_info *xsk_configure_umem(void *buffer, size_t size, size_t frame_size)
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
		return NULL;
    }

	ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq, &cfg);
	if (ret) {
        return NULL;
    }

	umem->buffer = buffer;
	return umem;
}

int xsk_populate_fill_ring(struct xsk_umem_info *umem, size_t frame_size)
{
	int ret, i;
	uint32_t idx;

	ret = xsk_ring_prod__reserve(&umem->fq,
				     XSK_RING_PROD__DEFAULT_NUM_DESCS, &idx);
	if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS)
		return -ret;
	for (i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i++)
		*xsk_ring_prod__fill_addr(&umem->fq, idx++) =
			i * frame_size;
	xsk_ring_prod__submit(&umem->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS);
	return 0;
}

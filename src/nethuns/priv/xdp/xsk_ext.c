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
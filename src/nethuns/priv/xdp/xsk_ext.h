#pragma once

#include <src/libbpf.h>
#include <src/xsk.h>
#include <linux/bpf.h>
#include <stdint.h>

struct xsk_umem_info {
	struct xsk_ring_prod fq;
	struct xsk_ring_cons cq;
	struct xsk_umem *umem;
	void *buffer;
};

struct xsk_socket_info {
	struct xsk_ring_cons rx;
	struct xsk_ring_prod tx;
	struct xsk_umem_info *umem;
	struct xsk_socket *xsk;
	unsigned long rx_npkts;
	unsigned long tx_npkts;
	unsigned long prev_rx_npkts;
	unsigned long prev_tx_npkts;
	uint32_t outstanding_tx;
};

struct xsk_umem_info *xsk_configure_umem(void *buffer, size_t size, size_t frame_size);
int xsk_populate_fill_ring(struct xsk_umem_info *umem, size_t frame_size);
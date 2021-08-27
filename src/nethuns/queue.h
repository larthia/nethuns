// Copyright 2021 Larthia, University of Pisa. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#pragma once

#include "misc/compiler.h"
#include <stdlib.h>
#include <string.h>


struct nethuns_spsc_queue
{
	struct
	{
		size_t head_cache;

	} consumer __cacheline_aligned;

	struct
	{
		size_t tail_cache;

	} producer __cacheline_aligned;

	struct
	{
		size_t head;

	} __cacheline_aligned;

	struct
	{
		size_t tail;

	} __cacheline_aligned;

	struct
	{
		size_t nslots_1;
		size_t size;
		void * mem;

	} __cacheline_aligned;
};


static inline
struct nethuns_spsc_queue *
nethuns_spsc_init(size_t nslots, size_t size)
{
	if (nslots & (nslots-1)) {
		return NULL;
	}

	struct nethuns_spsc_queue *fifo = (struct nethuns_spsc_queue *)
		calloc(1, sizeof(struct nethuns_spsc_queue) + nslots * size);

	if (fifo != NULL)
	{
		fifo->nslots_1 = nslots-1;
		fifo->size = size;
		fifo->mem  = calloc(1, nslots*size);
		fifo->head = 0;
		fifo->tail = 0;
		fifo->producer.tail_cache = 0;
		fifo->consumer.head_cache = 0;
	}
	return fifo;
}

static inline
void *nethuns_slot_addr(struct nethuns_spsc_queue *fifo, size_t idx) {
	return (char *)fifo->mem + fifo->size * idx;
}

static inline
bool nethuns_spsc_is_empty(struct nethuns_spsc_queue const *fifo)
{
	return  __atomic_load_n(&fifo->head, __ATOMIC_RELAXED) ==
			__atomic_load_n(&fifo->tail, __ATOMIC_RELAXED);
}


static inline
bool nethuns_spsc_is_full(struct nethuns_spsc_queue const *fifo)
{
	return ((__atomic_load_n(&fifo->head, __ATOMIC_RELAXED) + 1) & (fifo->nslots_1)) ==
			__atomic_load_n(&fifo->tail, __ATOMIC_RELAXED);
}


static inline
size_t nethuns_spsc_distance(struct nethuns_spsc_queue const *fifo, size_t h, size_t t)
{
	return (h - t) & fifo->nslots_1;
}


static inline
void nethuns_spsc_consumer_sync(struct nethuns_spsc_queue *fifo)
{
	fifo->consumer.head_cache = __atomic_load_n(&fifo->head, __ATOMIC_ACQUIRE);
}


static inline
void nethuns_spsc_producer_sync(struct nethuns_spsc_queue *fifo)
{
	fifo->producer.tail_cache = __atomic_load_n(&fifo->tail, __ATOMIC_ACQUIRE);
}


static inline
size_t nethuns_spsc_len(struct nethuns_spsc_queue *fifo)
{
	size_t h = __atomic_load_n(&fifo->head, __ATOMIC_RELAXED);
	size_t t = __atomic_load_n(&fifo->tail, __ATOMIC_RELAXED);
	return nethuns_spsc_distance(fifo, h, t);
}


static inline
size_t nethuns_spsc_next_index(struct nethuns_spsc_queue *fifo, size_t value)
{
	return (value + 1) & fifo->nslots_1;
}


static inline
size_t nethuns_spsc_push(struct nethuns_spsc_queue *fifo, void *elem)
{
    size_t w = __atomic_load_n(&fifo->head, __ATOMIC_RELAXED);
    size_t r = fifo->producer.tail_cache;
    size_t next = nethuns_spsc_next_index(fifo, w);

	if (next == r) {
		r = fifo->producer.tail_cache = __atomic_load_n(&fifo->tail, __ATOMIC_ACQUIRE);
		if (next == r) {
			return 0;
		}
	}

	memcpy(nethuns_slot_addr(fifo, w), elem, fifo->size);

	__atomic_store_n(&fifo->head, next, __ATOMIC_RELEASE);

    return nethuns_spsc_distance(fifo, next, r);
}


static inline
void *nethuns_spsc_pop(struct nethuns_spsc_queue *fifo)
{
    size_t w = fifo->consumer.head_cache;
    size_t r = __atomic_load_n(&fifo->tail, __ATOMIC_RELAXED);
    size_t next;
    void *elem;

	if (w == r) {
		w = fifo->consumer.head_cache = __atomic_load_n(&fifo->head, __ATOMIC_ACQUIRE);
		if (w == r)
			return NULL;
	}

	elem = nethuns_slot_addr(fifo, r);

	next = nethuns_spsc_next_index(fifo, r);

	__atomic_store_n(&fifo->tail, next, __ATOMIC_RELEASE);

	return elem;
}


static inline
void *nethuns_spsc_peek(struct nethuns_spsc_queue *fifo)
{
    size_t w = fifo->consumer.head_cache;
    size_t r = __atomic_load_n(&fifo->tail, __ATOMIC_RELAXED);

	if (w == r) {
		w = fifo->consumer.head_cache = __atomic_load_n(&fifo->head, __ATOMIC_ACQUIRE);
		if (w == r)
			return NULL;
	}

	return nethuns_slot_addr(fifo, r);
}


static inline
void nethuns_spsc_consume(struct nethuns_spsc_queue *fifo)
{
	size_t next = nethuns_spsc_next_index(fifo, fifo->tail);
	__atomic_store_n(&fifo->tail, next, __ATOMIC_RELEASE);
}


static inline
void nethuns_spsc_free(struct nethuns_spsc_queue *fifo, void (*free_)(void *))
{
	void *ptr;

	if (free_) {
		while ((ptr = nethuns_spsc_pop(fifo)))
			free_(ptr);
	}

	free(fifo->mem);
	free(fifo);
}

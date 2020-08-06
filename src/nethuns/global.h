#pragma once

#include <pthread.h>
#include <stdint.h>

#ifndef _GNU_SOURCE 
#define _GNU_SOURCE
#endif

#include "util/hashmap.h"
#include "util/compiler.h"

#if defined (NETHUNS_USE_XDP)
#include <linux/bpf.h>
#endif

struct nethuns_netinfo {
    int      promisc_refcnt;
    int      xdp_prog_refcnt;
    uint32_t xdp_prog_id;
};

static inline
void nethuns_netinfo_init(struct nethuns_netinfo *info)
{
    info->promisc_refcnt  = 0;
    info->xdp_prog_refcnt = 0;
    info->xdp_prog_id     = 0;
}

static inline
void nethuns_netinfo_fini(__maybe_unused struct nethuns_netinfo *info)
{
}

struct nethuns_global
{
    pthread_mutex_t m;
    struct hashmap_s netinfo_map;
};

#ifdef __cplusplus
extern "C" {
#endif

	extern struct nethuns_global __nethuns_global;

	extern void __attribute__((constructor)) nethuns_global_init();
	extern void __attribute__((destructor)) nethuns_global_fini();

	static inline
	void nethuns_lock_global()
	{
	    pthread_mutex_lock(&__nethuns_global.m);
	}
	
	static inline
	void nethuns_unlock_global()
	{
	    pthread_mutex_unlock(&__nethuns_global.m);
	}

	struct nethuns_netinfo *nethuns_lookup_netinfo(const char *);
	struct nethuns_netinfo *nethuns_create_netinfo(const char *);

#ifdef __cplusplus
}
#endif


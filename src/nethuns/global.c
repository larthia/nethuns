/**
 * Copyright 2021 Larthia, University of Pisa. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#if defined __linux__
#include <sys/resource.h>
#endif

#include "api.h"
#include "global.h"
#include "define.h"

struct nethuns_global __nethuns_global;

#ifdef NETHUNS_USE_LIBPCAP
int nethuns_check_libpcap(size_t hsize, char *errbuf);
#endif
#ifdef NETHUNS_USE_NETMAP
int nethuns_check_netmap(size_t hsize, char *errbuf);
#endif
#ifdef NETHUNS_USE_XDP
int nethuns_check_xdp(size_t hsize, char *errbuf);
#endif
#ifdef NETHUNS_USE_TPACKET_V3
int nethuns_check_tpacket_v3(size_t hsize, char *errbuf);
#endif

void
nethuns_init_(size_t hsize, int socket)
{
    char errbuf[NETHUNS_ERRBUF_SIZE];

    switch (socket) {
#ifdef NETHUNS_USE_LIBPCAP
    case NETHUNS_SOCKET_LIBPCAP: {
        if (nethuns_check_libpcap(hsize, errbuf) < 0) {
            nethuns_fprintf(stderr, "%s\n", errbuf);
		    exit(EXIT_FAILURE);
        }
    } break;
#endif
#ifdef NETHUNS_USE_NETMAP
    case NETHUNS_SOCKET_NETMAP: {
        if (nethuns_check_netmap(hsize, errbuf) < 0) {
            nethuns_fprintf(stderr, "%s\n", errbuf);
		    exit(EXIT_FAILURE);
        }
    } break;
#endif
#ifdef NETHUNS_USE_XDP
    case NETHUNS_SOCKET_XDP: {
        if (nethuns_check_xdp(hsize, errbuf) < 0) {
            nethuns_fprintf(stderr, "%s\n", errbuf);
		    exit(EXIT_FAILURE);
        }
    } break;
#endif
#ifdef NETHUNS_USE_TPACKET_V3
    case NETHUNS_SOCKET_TPACKET3: {
        if (nethuns_check_tpacket_v3(hsize, errbuf) < 0) {
            nethuns_fprintf(stderr, "%s\n", errbuf);
            exit(EXIT_FAILURE);
        }
    } break;
#endif
    default: {
        nethuns_fprintf(stderr, "unsupported socket type %d\n", socket);
        exit(EXIT_FAILURE);
    }
    }

    pthread_mutex_init(&__nethuns_global.m, NULL);
    nethuns_fprintf(stderr, "initializing %s...\n", nethuns_version());

    if (hashmap_create(64, &__nethuns_global.netinfo_map)) {
		nethuns_fprintf(stderr, "could not create netinfo hashmap\n");
		exit(EXIT_FAILURE);
    }

#if defined __linux__
    {
        struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};

        if (setrlimit(RLIMIT_MEMLOCK, &r)) {
		    nethuns_fprintf(stderr, "setrlimit(RLIMIT_MEMLOCK) \"%s\"\n", strerror(errno));
		    exit(EXIT_FAILURE);
	    }
    }
#endif
}

void __attribute__ ((destructor))
nethuns_fini() {
    if (__nethuns_global.netinfo_map.data != NULL) {
        nethuns_fprintf(stderr, "cleanup...\n");
        hashmap_destroy(&__nethuns_global.netinfo_map);
    }
}

struct nethuns_netinfo *
nethuns_lookup_netinfo(const char *dev)
{
    return  hashmap_get(&__nethuns_global.netinfo_map, dev, strlen(dev));
}

struct nethuns_netinfo *
nethuns_create_netinfo(const char *dev)
{
    void * data = malloc(sizeof(struct nethuns_netinfo));
    nethuns_netinfo_init(data);

    if (hashmap_put(&__nethuns_global.netinfo_map, dev, strlen(dev), data) != 0)
    {
        nethuns_netinfo_fini(data);
        free(data);
        return NULL;
    }
    return data;
}

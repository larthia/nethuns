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

#include "global.h"
#include "api.h"

struct nethuns_global __nethuns_global;


void __attribute__ ((constructor))
nethuns_global_init() {

    pthread_mutex_init(&__nethuns_global.m, NULL);

    nethuns_fprintf(stderr, "initializing...\n");

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
nethuns_global_fini() {
    nethuns_fprintf(stderr, "cleanup...\n");
    hashmap_destroy(&__nethuns_global.netinfo_map);
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

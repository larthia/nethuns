#include "global.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#if defined (NETHUNS_USE_XDP)
#include <sys/resource.h>
#endif

struct nethuns_global __nethuns_global;


void __attribute__ ((constructor))
nethuns_global_init() {

    pthread_mutex_init(&__nethuns_global.m, NULL);
    fprintf(stderr, "nethuns: initializing...\n");

    if (hashmap_create(64, &__nethuns_global.netinfo)) {
		fprintf(stderr, "nethuns: could not create netinfo hashmap\n");
		exit(EXIT_FAILURE);
    }

#if defined (NETHUNS_USE_XDP)
    {
        struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};

        if (setrlimit(RLIMIT_MEMLOCK, &r)) {
		    fprintf(stderr, "nethuns: setrlimit(RLIMIT_MEMLOCK) \"%s\"\n", strerror(errno));
		    exit(EXIT_FAILURE);
	    }
    }
#endif
}

void __attribute__ ((destructor))
nethuns_global_fini() {
    fprintf(stderr, "nethuns: cleanup...\n");
    hashmap_destroy(&__nethuns_global.netinfo);
}

struct nethuns_netinfo *
nethuns_lookup_netinfo(const char *dev)
{
    return  hashmap_get(&__nethuns_global.netinfo, dev, strlen(dev));
}

struct nethuns_netinfo *
nethuns_create_netinfo(const char *dev)
{
    void * data = calloc(sizeof(struct nethuns_netinfo), 1);
    if (hashmap_put(&__nethuns_global.netinfo, dev, strlen(dev), data) != 0) {
        free(data);
        return NULL;
    }
    return data;
}

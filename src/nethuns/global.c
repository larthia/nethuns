#include "global.h"
#include <stdio.h>
#include <stdlib.h>

struct nethuns_global __nethuns_global;


void __attribute__ ((constructor)) 
nethuns_global_init() {
    pthread_mutex_init(&__nethuns_global.m, NULL);
    fprintf(stderr, "nethuns: initializing...\n");
    hcreate_r(64, &__nethuns_global.netinfo);
}

void __attribute__ ((destructor))
nethuns_global_fini() {
    fprintf(stderr, "nethuns: cleanup...\n");
    hdestroy_r(&__nethuns_global.netinfo);
}

struct nethuns_net_info *
nethuns_lookup_netinfo(const char *dev)
{
    ENTRY pair;
    ENTRY *ret;
    pair.key = (char *)dev;

    if (hsearch_r(pair, FIND, &ret, &__nethuns_global.netinfo) < 0) {
        return NULL;
    }

    if (ret == NULL)
        return NULL;
    return ret->data;
}

struct nethuns_net_info *
nethuns_create_netinfo(const char *dev)
{
    ENTRY pair;
    ENTRY *ret;
    pair.key = (char *)dev;
    pair.data = calloc(sizeof(struct nethuns_net_info), 1);
    if (hsearch_r(pair, ENTER, &ret, &__nethuns_global.netinfo) < 0) {
        return NULL;
    }
    return ret->data;
}

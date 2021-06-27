#include "sockets/base.h"

void
nethuns_set_filter(nethuns_socket_t * s, nethuns_filter_t filter, void *ctx)
{
    nethuns_socket(s)->filter = filter;
    nethuns_socket(s)->filter_ctx = ctx;
}

void
nethuns_clear_filter(nethuns_socket_t * s)
{
    nethuns_socket(s)->filter = NULL;
    nethuns_socket(s)->filter_ctx = NULL;
}
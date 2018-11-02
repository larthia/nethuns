#include <string.h>
#include <stdio.h>
#include <errno.h>

#include "types.h"

void
nethuns_perror(char *buf, char *msg)
{
    if (errno != 0)
    {
        snprintf(buf, NETHUNS_ERRBUF_SIZE, "nethuns: %s (%s)", msg, strerror(errno));
    }
    else
    {
        snprintf(buf, NETHUNS_ERRBUF_SIZE, "nethuns: %s", msg);
    }
}



#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>

#include "types.h"

void
nethuns_perror(char *buf, char *msg, ...)
{
    int n;

    va_list ap;
    va_start(ap, msg);

    strcpy(buf, "nethuns: ");

    n = vsnprintf(buf+9, NETHUNS_ERRBUF_SIZE-9, msg, ap);

    if (errno != 0)
    {
        snprintf(buf+9+n, NETHUNS_ERRBUF_SIZE-9 - n, " (%s)", strerror(errno));
    }

    va_end(ap);
}

const char *
nethuns_version ()
{
    static const char ver[] = "nethuns v1.0";
    return ver;
}

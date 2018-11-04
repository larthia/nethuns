#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>

#include "types.h"

void
nethuns_perror(char *buf, char *msg, ...)
{
    va_list ap;
    va_start(ap, msg);

    char pattern[NETHUNS_ERRBUF_SIZE];
    strcpy(pattern, "nethuns: ");
    strcat(pattern, msg);

    if (errno != 0)
    {
        int r = vsnprintf(buf, NETHUNS_ERRBUF_SIZE, pattern, ap);
        snprintf(buf+r, NETHUNS_ERRBUF_SIZE - r, " (%s)", strerror(errno));
    }
    else
    {
        vsnprintf(buf, NETHUNS_ERRBUF_SIZE, "nethuns: %s", ap);
    }

    va_end(ap);
}

const char *
nethuns_version ()
{
    static const char ver[] = "nethuns v1.0";
    return ver;
}

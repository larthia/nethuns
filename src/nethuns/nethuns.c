#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>

#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>

#include "nethuns.h"


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


int
nethuns_if_ioctl(nethuns_socket_t *s, const char *devname, unsigned long what, uint32_t *flags)
{
    struct ifreq ifr;
    int rv;

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        nethuns_perror(nethuns_base(s)->errbuf, "ioctl: could not open socket");
        return -1;
    }

    bzero(&ifr, sizeof(ifr));
    strncpy(ifr.ifr_name, devname, sizeof(ifr.ifr_name));

    if (what == SIOCSIFFLAGS)
        ifr.ifr_flags = *flags;

    rv = ioctl(fd, what, &ifr);
    if (rv < 0)
    {
        nethuns_perror(nethuns_base(s)->errbuf, "ioctl");
        close (fd);
        return -1;
    }

    if (what == SIOCGIFFLAGS)
        *flags = ifr.ifr_flags;

    close (fd);
    return 0;
}


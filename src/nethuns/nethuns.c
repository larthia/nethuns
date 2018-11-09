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
nethuns_ioctl_if(nethuns_socket_t *s, const char *devname, unsigned long what, uint32_t *flags)
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


int
nethuns_set_if_promisc(nethuns_socket_t *s, char const *devname)
{
    uint32_t flags;

    if (nethuns_ioctl_if(s, devname, SIOCGIFFLAGS, &flags) < 0)
        return -1;

    if (!(flags & IFF_PROMISC)) {
        flags |= IFF_PROMISC;
        if (nethuns_ioctl_if(s, devname, SIOCSIFFLAGS, &flags) < 0)
            return -1;
        nethuns_base(s)->clear_promisc = true;
    }

    return 0;
}


int
nethuns_clear_if_promisc(nethuns_socket_t *s, char const *devname)
{
    uint32_t flags;
    if (nethuns_ioctl_if(s, devname, SIOCGIFFLAGS, &flags) < 0)
        return -1;

    flags &= ~IFF_PROMISC;
    if (nethuns_ioctl_if(s, devname, SIOCSIFFLAGS, &flags) < 0)
        return -1;

    fprintf(stderr, "clear promisc!\n");
    return 0;
}


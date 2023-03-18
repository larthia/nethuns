/**
 * Copyright 2021 Larthia, University of Pisa. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>

#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>

#include "sockets/base.h"
#include "global.h"
#include "define.h"
#include "types.h"
#include "api.h"

void
nethuns_fprintf(FILE *out, const char *msg, ...)
{
    va_list ap;
    va_start(ap, msg);
    fprintf(out, "nethuns: ");
    vfprintf(out, msg, ap);
    va_end(ap);
}


void
nethuns_perror(char *buf, const char *msg, ...)
{
    va_list ap;
    va_start(ap, msg);
    int n;

    n = vsnprintf(buf, NETHUNS_ERRBUF_SIZE, msg, ap);
    if (errno != 0) {
        snprintf(buf+n, NETHUNS_ERRBUF_SIZE - n, " (%s)", strerror(errno));
    }
    va_end(ap);
}


const char *
nethuns_version ()
{
    static const char ver[] = "nethuns v3.0";
    return ver;
}


int
nethuns_ioctl_if(nethuns_socket_t *s, const char *devname, unsigned long what, uint32_t *flags)
{
    struct ifreq ifr;
    int rv;

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        nethuns_perror(nethuns_socket(s)->errbuf, "ioctl: could not open socket");
        return -1;
    }

    bzero(&ifr, sizeof(ifr));
    strncpy(ifr.ifr_name, devname, sizeof(ifr.ifr_name)-1);

    if (what == SIOCSIFFLAGS)
        ifr.ifr_flags = *flags;

    rv = ioctl(fd, what, &ifr);
    if (rv < 0)
    {
        nethuns_perror(nethuns_socket(s)->errbuf, "ioctl");
        close (fd);
        return -1;
    }

    if (what == SIOCGIFFLAGS)
        *flags = ifr.ifr_flags;

    close (fd);
    return 0;
}


void
__nethuns_free_base(nethuns_socket_t *s)
{
    free(nethuns_socket(s)->devname);
    free(nethuns_socket(s)->rx_ring.ring);
}


int
__nethuns_set_if_promisc(nethuns_socket_t *s, char const *devname)
{
    uint32_t flags;
    struct nethuns_netinfo *info;
    bool do_promisc;

    if (nethuns_ioctl_if(s, devname, SIOCGIFFLAGS, &flags) < 0)
        return -1;

    nethuns_lock_global();

    info = nethuns_lookup_netinfo(devname);
    if (info == NULL) {
        info = nethuns_create_netinfo(devname);
        if (info == NULL) {
            nethuns_unlock_global();
            return -1;
        }

        info->promisc_refcnt = (flags & IFF_PROMISC) ? 1 : 0;
    }

    info->promisc_refcnt++;

    do_promisc = !(flags & IFF_PROMISC);

    if (do_promisc)
    {
        flags |= IFF_PROMISC;
        if (nethuns_ioctl_if(s, devname, SIOCSIFFLAGS, &flags) < 0)
        {
            info->promisc_refcnt--;
            nethuns_unlock_global();
            return -1;
        }
    }

    if (do_promisc)
        nethuns_fprintf(stderr, "device %s promisc mode set\n", devname);
    else
        nethuns_fprintf(stderr, "device %s (already) promisc mode set\n", devname);

    nethuns_unlock_global();
    return 0;
}


int
__nethuns_clear_if_promisc(nethuns_socket_t *s, char const *devname)
{
    uint32_t flags;
    struct nethuns_netinfo *info;
    bool do_clear = false;

    if (nethuns_ioctl_if(s, devname, SIOCGIFFLAGS, &flags) < 0)
        return -1;

    nethuns_lock_global();

    info = nethuns_lookup_netinfo(devname);
    if (info != NULL) {
        if(--info->promisc_refcnt <= 0) {
            do_clear = true;
        }
    }

    if (do_clear) {
        flags &= ~IFF_PROMISC;
        if (nethuns_ioctl_if(s, devname, SIOCSIFFLAGS, &flags) < 0) {
            nethuns_unlock_global();
            return -1;
        }
        nethuns_fprintf(stderr, "device %s promisc mode unset\n", devname);
    }

    nethuns_unlock_global();
    return 0;
}

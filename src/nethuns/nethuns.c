#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>

#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>

#include "nethuns.h"
#include "global.h"


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


void
__nethuns_free_base(nethuns_socket_t *s)
{
    free(nethuns_socket(s)->devname);
    free(nethuns_socket(s)->ring.ring);
}


int
__nethuns_set_if_promisc(nethuns_socket_t *s, char const *devname)
{
    uint32_t flags;
    struct nethuns_net_info *info;

    if (nethuns_ioctl_if(s, devname, SIOCGIFFLAGS, &flags) < 0)
        return -1;
    
    nethuns_lock_netinfo();

    info = nethuns_lookup_netinfo(devname);
    if (info == NULL) {
        info = nethuns_create_netinfo(devname);
        if (info == NULL) {
            nethuns_unlock_netinfo();
            return -1;
        }

        info->promisc_refcnt = (flags & IFF_PROMISC) ? 1 : 0;
    }

    info->promisc_refcnt++;

    if (!(flags & IFF_PROMISC)) {
        flags |= IFF_PROMISC;
        if (nethuns_ioctl_if(s, devname, SIOCSIFFLAGS, &flags) < 0)
        {
            info->promisc_refcnt--;
            nethuns_unlock_netinfo();
            return -1;
        }
    }
        
    fprintf(stderr, "nethuns: device %s promisc mode set\n", devname);
    nethuns_unlock_netinfo();
    return 0;
}


int
__nethuns_clear_if_promisc(nethuns_socket_t *s, char const *devname)
{
    uint32_t flags;
    struct nethuns_net_info *info;
    bool do_clear = false;

    if (nethuns_ioctl_if(s, devname, SIOCGIFFLAGS, &flags) < 0)
        return -1;
    
    nethuns_lock_netinfo();
    
    info = nethuns_lookup_netinfo(devname);
    if (info != NULL) {
        if(--info->promisc_refcnt <= 0) {
            do_clear = true;
        }
    }

    if (do_clear) {
        flags &= ~IFF_PROMISC;
        if (nethuns_ioctl_if(s, devname, SIOCSIFFLAGS, &flags) < 0) {
            nethuns_unlock_netinfo();
            return -1;
        }
        fprintf(stderr, "nethuns: device %s promisc mode unset\n", devname);
    }
    nethuns_unlock_netinfo();
    return 0;
}


#include "internals/tpacketv3.h"


struct nethuns_socket *
nethuns_open(size_t blocksize, size_t numblocks, size_t packetsize)
{
    struct nethuns_socket *sock;
    int fd;

    fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd == -1)
        return NULL;

    sock = malloc(sizeof(struct nethuns_socket));

    sock->fd = fd;

    return sock;
}


int nethuns_close(struct nethuns_socket *sock)
{
    close(sock->fd);
    free(sock);
    return 0;
}

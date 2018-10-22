# pragma once

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <unistd.h>
#include <signal.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>


struct ring
{
    struct iovec *rd;
    uint8_t *map;
    struct tpacket_req3 req;
};


struct nethuns_socket
{
    int fd;
    struct ring ring;
};



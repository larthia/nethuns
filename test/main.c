#include <nethuns.h>
#include <stdio.h>

int
main(int argc, char *argv[])
{
    nethuns_socket_t s = nethuns_open(4,1024,2048);

    if (nethuns_bind(s, "eth0") < 0)
    {
        return -1;
    }

    unsigned char *frame;
    nethuns_pkthdr_t pkthdr;

    nethuns_set_consumers(s, 1);

    for(;;)
    {
        unsigned int block;

        if ((block = nethuns_recv(s, &pkthdr, &frame)))
        {
            printf("packet (block:%d)!\n", block);
            nethuns_release(s, pkthdr, block, 0);
        }
	}

    nethuns_close(s);
    return 0;
}


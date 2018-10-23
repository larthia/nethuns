#include <nethuns.h>
#include <stdio.h>

int
main(int argc, char *argv[])
{
    nethuns_socket_t s = nethuns_open(2,1024,2048);

    if (nethuns_bind(s, "eth0") < 0)
    {
        return -1;
    }

    unsigned char *frame;
    nethuns_pkthdr_t *pkthdr;

    nethuns_set_consumers(s, 1);

    for(;;)
    {
        uint64_t block;

        if ((block = nethuns_recv(s, &pkthdr, &frame)))
        {
            printf("packet!\n");
            nethuns_release(s, pkthdr, block, 0);
        }

        // usleep(100000);
    }

    nethuns_close(s);
    return 0;
}


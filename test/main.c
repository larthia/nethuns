#include <nethuns.h>
#include <stdio.h>

void dump_packet(nethuns_pkthdr_t *hdr, unsigned char *frame)
{
    int i = 0;

    printf("%u:%u snap:%u len:%u mac:%u", hdr->tp_sec, hdr->tp_nsec, hdr->tp_snaplen, hdr->tp_len, hdr->tp_mac);
    for(; i < 14; i++)
    {
        printf("%02x ", frame[i]);
    }
    printf("\n");
}


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

    nethuns_set_consumer(s, 1);

    for(;;)
    {
        uint64_t block;

        if ((block = nethuns_recv(s, &pkthdr, &frame)))
        {
            dump_packet(pkthdr, frame);
            nethuns_release(s, pkthdr, block, 0);
        }

        // usleep(100000);
    }

    nethuns_close(s);
    return 0;
}


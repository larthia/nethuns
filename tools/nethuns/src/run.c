#include <nethuns/nethuns.h>
#include <unistd.h>

#include "hdr/dump.h"
#include "hdr/options.h"

static int
run_capture(struct options *opt) {
    char errbuf[NETHUNS_ERRBUF_SIZE];
    nethuns_socket_t *s;

    nethuns_init();

    s = nethuns_open(&opt->sopt, errbuf);
    if (!s)
    {
        fprintf(stderr, "%s\n", errbuf);
        return -1;
    }

    if (nethuns_bind(s, opt->dev, opt->queue) < 0)
    {
        fprintf(stderr, "%s\n", nethuns_error(s));
        return -1;
    }

    const unsigned char *frame;
    const nethuns_pkthdr_t *pkthdr;

    for(uint64_t i =0; i < opt->count;)
    {
        uint64_t pkt_id;

        if ((pkt_id = nethuns_recv(s, &pkthdr, &frame)))
        {
            dump_frame(pkthdr, frame, opt->verbose);
            nethuns_rx_release(s, pkt_id);
            i++;
        } else {
            usleep(1);
        }
    }

    printf("done.\n");
    nethuns_close(s);
    return 0;
}

static int
run_meter(struct options *opt) {
    char errbuf[NETHUNS_ERRBUF_SIZE];
    nethuns_socket_t *s;

    nethuns_init();
    return 0;
}

int
run(struct options *opt) {
    if (opt->meter)
        return run_meter(opt);
    else
        return run_capture(opt);
}

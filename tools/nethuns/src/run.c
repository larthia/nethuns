#include <nethuns/nethuns.h>
#include <unistd.h>
#include <pthread.h>

#include "hdr/dump.h"
#include "hdr/options.h"

extern int sig_shutdown;

struct targs {
    struct options *opt;
    int id;
};

static void *
run_capture(void *_args) {
    struct targs *args = (struct targs *)(_args);

    char errbuf[NETHUNS_ERRBUF_SIZE];
    nethuns_socket_t *s;
    struct options *opt = args->opt;
    nethuns_init();

    s = nethuns_open(&opt->sopt, errbuf);
    if (!s)
    {
        fprintf(stderr, "%s\n", errbuf);
        return (void *)-1;
    }

    if (nethuns_bind(s, opt->dev[args->id].name, opt->dev[args->id].queue) < 0)
    {
        fprintf(stderr, "%s\n", nethuns_error(s));
        return (void *)-1;
    }

    const unsigned char *frame;
    const nethuns_pkthdr_t *pkthdr;

    for(uint64_t i =0; i < opt->count;)
    {
        uint64_t pkt_id;

        if ((pkt_id = nethuns_recv(s, &pkthdr, &frame)))
        {
            dump_frame(pkthdr, frame, opt->dev[args->id].name, opt->dev[args->id].queue, opt->verbose);
            nethuns_rx_release(s, pkt_id);
            i++;
        } else {
            if (__atomic_load_n(&sig_shutdown, __ATOMIC_RELAXED)) {
                goto done;
            }
            usleep(1);
        }
    }

done:
    printf("done.\n");
    nethuns_close(s);
    return (void *)0;
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
    if (opt->meter) {
        return run_meter(opt);
    }

    pthread_t threads[MAX_DEVICES];

    /* run the threads... */

    for (int i = 0; i < opt->num_devs; i++)
    {
        pthread_t thread;
        int err;
        struct targs *nargs = malloc(sizeof(struct targs));

        nargs->opt = opt;
        nargs->id = i;
        err = pthread_create(&thread, NULL, run_capture, nargs);
        if (err != 0) {
            fprintf(stderr, "could not create a capture thread: %s\n", strerror(err));
        }
    }

    /* ...and wait for them to complete the job */
    for(int i = 0; i < opt->num_devs; i++) {
        pthread_join(threads[i], NULL);
    }
}

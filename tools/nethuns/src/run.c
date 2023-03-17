#include <nethuns/nethuns.h>
#include <unistd.h>
#include <pthread.h>

#include "hdr/dump.h"
#include "hdr/options.h"
#include "hdr/stats.h"

extern int sig_shutdown;

struct stats global_stats[MAX_DEVICES];

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


static void *
run_meter(void *_args) {

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

    uint64_t pkt_count = 0;
    uint64_t byte_count = 0;

    struct stats *st = &global_stats[args->id];

    for(uint64_t i =0; i < opt->count;)
    {
        uint64_t pkt_id;

        if ((pkt_id = nethuns_recv(s, &pkthdr, &frame)))
        {
            i++;
            if (opt->relaxed_stats) {
                pkt_count++;
                byte_count += nethuns_len(pkthdr);
                if ((pkt_count & 127) == 0) {
                    __atomic_fetch_add(&st->pkt_count, pkt_count, __ATOMIC_RELAXED);
                    __atomic_fetch_add(&st->byte_count, byte_count, __ATOMIC_RELAXED);
                    pkt_count = 0;
                    byte_count = 0;
                }
            } else {
                __atomic_fetch_add(&st->pkt_count, 1, __ATOMIC_RELAXED);
                __atomic_fetch_add(&st->byte_count, nethuns_len(pkthdr), __ATOMIC_RELAXED);
            }

            nethuns_rx_release(s, pkt_id);
        } else {
            if (__atomic_load_n(&sig_shutdown, __ATOMIC_RELAXED)) {
                goto done;
            }
            usleep(1);
        }
    }
done:
    __atomic_fetch_add(&st->pkt_count, pkt_count, __ATOMIC_RELAXED);
    __atomic_fetch_add(&st->byte_count, byte_count, __ATOMIC_RELAXED);
    nethuns_close(s);
    printf("done.\n");
    return (void *)0;
}

void *
meter(void *opt)
{
    uint64_t prev_pkt_count = 0;
    uint64_t prev_byte_count = 0;
    uint64_t pkt_count = 0;
    uint64_t byte_count = 0;

    for(;;sleep(1)) {

        for(int i = 0; i < ((struct options *)opt)->num_devs; i++) {
            pkt_count += __atomic_load_n(&global_stats[i].pkt_count, __ATOMIC_RELAXED);
            byte_count += __atomic_load_n(&global_stats[i].byte_count, __ATOMIC_RELAXED);
            __atomic_store_n(&global_stats[i].pkt_count, 0, __ATOMIC_RELAXED);
            __atomic_store_n(&global_stats[i].byte_count, 0, __ATOMIC_RELAXED);
        }

        uint64_t pkt_delta = pkt_count - prev_pkt_count;
        uint64_t byte_delta = byte_count - prev_byte_count;

        printf("packets: %" PRIu64 ", bytes: %" PRIu64", rate: %" PRIu64 " pps, %" PRIu64" bps\n", pkt_count, byte_count, pkt_delta, byte_delta * 8);

        prev_pkt_count = pkt_count;
        prev_byte_count = byte_count;

        if (__atomic_load_n(&sig_shutdown, __ATOMIC_RELAXED)) {
            return NULL;
        }
    }

    return NULL;
}

int
run(struct options *opt) {
    pthread_t threads[MAX_DEVICES];

    /* run the threads... */

    void *(*callback)(void *) = opt->meter ? run_meter : run_capture;

    for (int i = 0; i < opt->num_devs; i++)
    {
        pthread_t thread;
        int err;
        struct targs *nargs = malloc(sizeof(struct targs));

        nargs->opt = opt;
        nargs->id = i;

        err = pthread_create(&thread, NULL, callback, nargs);
        if (err != 0) {
            fprintf(stderr, "could not create a capture thread: %s\n", strerror(err));
        }
    }

    pthread_t mtr;
    pthread_create(&mtr, NULL, meter, opt);

    /* ...and wait for them to complete the job */
    for(int i = 0; i < opt->num_devs; i++) {
        pthread_join(threads[i], NULL);
    }

    pthread_join(mtr, NULL);
    return 0;
}

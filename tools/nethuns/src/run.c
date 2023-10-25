#include <nethuns/nethuns.h>
#include <unistd.h>
#include <pthread.h>

#include "hdr/dump.h"
#include "hdr/options.h"
#include "hdr/stats.h"
#include "nethuns/api.h"

#include <stdio.h>
#include <inttypes.h>

extern int sig_shutdown;

struct stats global_stats[MAX_DEVICES];

struct targs {
    struct options *opt;
    int id;
};


static void *
run_capture_dev(void *_args)
{
    char errbuf[NETHUNS_ERRBUF_SIZE];
    struct targs *args = (struct targs *)(_args);
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

    struct stats *st = &global_stats[args->id];

    for(uint64_t i = 0; i < opt->count;)
    {
        uint64_t pkt_id;

        pkt_id = nethuns_recv(s, &pkthdr, &frame);
        if (nethuns_pkt_is_valid(pkt_id))
        {
            dump_frame(pkthdr, frame, opt->dev[args->id].name, opt->dev[args->id].queue, opt->verbose);

            __atomic_fetch_add(&st->pkt_count, 1, __ATOMIC_RELAXED);
            __atomic_fetch_add(&st->byte_count, nethuns_len(pkthdr), __ATOMIC_RELAXED);

            nethuns_rx_release(s, pkt_id);
            i++;
        } else {
            if(nethuns_pkt_is_err(pkt_id)) {
                break;
            }
            usleep(1);
        }

        if (__atomic_load_n(&sig_shutdown, __ATOMIC_RELAXED)) {
            break;
        }
    }

    nethuns_close(s);
    return (void *)0;
}

static void *
run_capture_file(void *_args)
{
    struct targs *args = (struct targs *)(_args);

    char errbuf[NETHUNS_ERRBUF_SIZE];
    nethuns_pcap_t *s;
    struct options *opt = args->opt;
    nethuns_init();

    s = nethuns_pcap_open(&opt->sopt, opt->dev[args->id].name, 0, errbuf);
    if (!s)
    {
        fprintf(stderr, "%s\n", errbuf);
        return (void *)-1;
    }

    const unsigned char *frame;
    const nethuns_pkthdr_t *pkthdr;

    struct stats *st = &global_stats[args->id];

    for(uint64_t i =0; i < opt->count;)
    {
        uint64_t pkt_id;

        pkt_id = nethuns_pcap_read(s, &pkthdr, &frame);
        if (nethuns_pkt_is_valid(pkt_id))
        {
            dump_frame(pkthdr, frame, opt->dev[args->id].name, opt->dev[args->id].queue, opt->verbose);

            __atomic_fetch_add(&st->pkt_count, 1, __ATOMIC_RELAXED);
            __atomic_fetch_add(&st->byte_count, nethuns_len(pkthdr), __ATOMIC_RELAXED);

            nethuns_rx_release(s, pkt_id);

            if (__atomic_load_n(&sig_shutdown, __ATOMIC_RELAXED)) {
                break;
            }
            i++;
            continue;
        } else {
            if(nethuns_pkt_is_eof(pkt_id) || nethuns_pkt_is_err(pkt_id) ||
                __atomic_load_n(&sig_shutdown, __ATOMIC_RELAXED)) {
                break;
            }
            usleep(1);
        }
    }

    nethuns_pcap_close(s);
    return (void *)0;

}

static void *
run_capture(void *_args) {
    struct targs *args = (struct targs *)(_args);
    struct options *opt = args->opt;

    if (strstr(opt->dev[args->id].name, ".pcap")) {
        return run_capture_file(_args);
    } else {
        return run_capture_dev(_args);
    }
}

static void *
run_meter_dev(void *_args) {
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

        pkt_id = nethuns_recv(s, &pkthdr, &frame);
        if (nethuns_pkt_is_valid(pkt_id))
        {
            i++;
            if (opt->meter >= 0) {
                pkt_count++;
                byte_count += nethuns_len(pkthdr);
                if ((pkt_count & ((1 << opt->meter)-1)) == 0) {
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
    return (void *)0;
}

static void *
run_meter_file(void *_args) {
    struct targs *args = (struct targs *)(_args);
    char errbuf[NETHUNS_ERRBUF_SIZE];
    nethuns_pcap_t *s;
    struct options *opt = args->opt;
    nethuns_init();

    s = nethuns_pcap_open(&opt->sopt, opt->dev[args->id].name, 0, errbuf);
    if (!s)
    {
        fprintf(stderr, "%s\n", errbuf);
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

        pkt_id = nethuns_pcap_read(s, &pkthdr, &frame);
        if (nethuns_pkt_is_valid(pkt_id))
        {
            i++;
            if (opt->meter >= 0) {
                pkt_count++;
                byte_count += nethuns_len(pkthdr);
                if ((pkt_count & ((1 << opt->meter)-1)) == 0) {
                    __atomic_fetch_add(&st->pkt_count, pkt_count, __ATOMIC_RELAXED);
                    __atomic_fetch_add(&st->byte_count, byte_count, __ATOMIC_RELAXED);
                    pkt_count = 0;
                    byte_count = 0;
                }
            } else {
                __atomic_fetch_add(&st->pkt_count, 1, __ATOMIC_RELAXED);
                __atomic_fetch_add(&st->byte_count, nethuns_len(pkthdr), __ATOMIC_RELAXED);
            }

            if (__atomic_load_n(&sig_shutdown, __ATOMIC_RELAXED)) {
                goto done;
            }

            nethuns_rx_release(s, pkt_id);
        } else {
            if(nethuns_pkt_is_eof(pkt_id)) {
                break;
            }
            if (__atomic_load_n(&sig_shutdown, __ATOMIC_RELAXED)) {
                goto done;
            }
            usleep(1);
        }
    }
done:
    __atomic_fetch_add(&st->pkt_count, pkt_count, __ATOMIC_RELAXED);
    __atomic_fetch_add(&st->byte_count, byte_count, __ATOMIC_RELAXED);
    nethuns_pcap_close(s);
    return (void *)0;
}


static void *
run_meter(void *_args) {
    struct targs *args = (struct targs *)(_args);
    struct options *opt = args->opt;

    if (strstr(opt->dev[args->id].name, ".pcap")) {
        return run_meter_file(_args);
    } else {
        return run_meter_dev(_args);
    }
}

void *
meter(void *opt)
{
    uint64_t pkt_count = 0;
    uint64_t byte_count = 0;

    uint64_t prev_pkt_count[MAX_DEVICES];
    uint64_t prev_byte_count[MAX_DEVICES];

    uint64_t total_prev_pkt_count = 0;
    uint64_t total_prev_byte_count = 0;

    for(;;sleep(1)) {

        for(int i = 0; i < ((struct options *)opt)->num_devs; i++) {
            uint64_t pkts = __atomic_load_n(&global_stats[i].pkt_count, __ATOMIC_RELAXED);
            uint64_t bytes = __atomic_load_n(&global_stats[i].byte_count, __ATOMIC_RELAXED);

            pkt_count +=  pkts - prev_pkt_count[i];
            byte_count += bytes - prev_byte_count[i];

            prev_pkt_count[i] = pkts;
            prev_byte_count[i] = bytes;
        }

        uint64_t pkt_delta = pkt_count - total_prev_pkt_count;
        uint64_t byte_delta = byte_count - total_prev_byte_count;

        uint64_t bandwdith = byte_delta * 8;

        if (bandwdith > 1e9) {
            printf("packets: %" PRIu64 ", bytes: %" PRIu64", rate: %" PRIu64 " pps, %.2lf Gbps\n", pkt_count, byte_count, pkt_delta, (double)bandwdith/1e9);
        } else if (bandwdith > 1e6) {
            printf("packets: %" PRIu64 ", bytes: %" PRIu64", rate: %" PRIu64 " pps, %.2lf Mbps\n", pkt_count, byte_count, pkt_delta, (double)bandwdith/1e6);
        } else if (bandwdith > 1e3) {
            printf("packets: %" PRIu64 ", bytes: %" PRIu64", rate: %" PRIu64 " pps, %.2lf Kbps\n", pkt_count, byte_count, pkt_delta, (double)bandwdith/1e3);
        } else {
            printf("packets: %" PRIu64 ", bytes: %" PRIu64", rate: %" PRIu64 " pps, %.2lf bps\n", pkt_count, byte_count, pkt_delta, (double)bandwdith);
        }

        total_prev_pkt_count = pkt_count;
        total_prev_byte_count = byte_count;

        if (__atomic_load_n(&sig_shutdown, __ATOMIC_RELAXED)) {
            return NULL;
        }
    }

    return NULL;
}

int
run(struct options *opt)
{
    pthread_t threads[MAX_DEVICES];

    /* run the threads... */

    void *(*callback)(void *) = opt->meter >= 0 ? run_meter : run_capture;

    for (int i = 0; i < opt->num_devs; i++)
    {
        int err;
        struct targs *nargs = malloc(sizeof(struct targs));

        nargs->opt = opt;
        nargs->id = i;

        err = pthread_create(&threads[i], NULL, callback, nargs);
        if (err != 0) {
            fprintf(stderr, "could not create a capture thread: %s\n", strerror(err));
        }
    }

    pthread_t mtr;

    if (opt->meter >= 0) {
        pthread_create(&mtr, NULL, meter, opt);
    }

    /* ...and wait for them to complete the job */
    for(int i = 0; i < opt->num_devs; i++) {
        pthread_join(threads[i], NULL);
    }

    __atomic_store_n(&sig_shutdown, 1, __ATOMIC_RELAXED);

    if (opt->meter >= 0) {
        pthread_join(mtr, NULL);
    }

    uint64_t total_pkt_count = 0;
    uint64_t total_byte_count = 0;

    for(int i = 0; i < ((struct options *)opt)->num_devs; i++) {
        total_pkt_count  += __atomic_load_n(&global_stats[i].pkt_count, __ATOMIC_RELAXED);
        total_byte_count += __atomic_load_n(&global_stats[i].byte_count, __ATOMIC_RELAXED);
    }

    printf("TOTAL packets: %" PRIu64 ", bytes: %" PRIu64 "\n", total_pkt_count, total_byte_count);
    sleep(1);
    return 0;
}

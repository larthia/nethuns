#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

#include "../nethuns.h"
#include "nethuns/internals/stub.h"

#include "pcap.h"
#include "ring.h"

#define TCPDUMP_MAGIC           0xa1b2c3d4
#define KUZNETZOV_TCPDUMP_MAGIC 0xa1b2cd34
#define FMESQUITA_TCPDUMP_MAGIC 0xa1b234cd
#define NAVTEL_TCPDUMP_MAGIC    0xa12b3c4d
#define NSEC_TCPDUMP_MAGIC      0xa1b23c4d


nethuns_pcap_t *
nethuns_pcap_open(struct nethuns_socket_options *opt, const char *filename, int mode, char *errbuf)
{
    struct nethuns_pcap_socket *pcap;
    FILE *f;
    struct  nethuns_ring *ring = NULL;
    uint32_t snaplen;

    if (!mode)
    {
        f = fopen(filename, "r");
        if (!f) {
            nethuns_perror(errbuf, "pcap_open");
            return NULL;
        }

        struct nethuns_pcap_file_header fh;
        if (fread(&fh, sizeof(fh), 1, f) != 1)
        {
            nethuns_perror(errbuf, "pcap_open: could not read pcap_file_header");
            fclose(f);
            return NULL;
        }

        snaplen = MIN(fh.snaplen, opt->packetsize);

        if (fh.magic != TCPDUMP_MAGIC &&
            fh.magic != KUZNETZOV_TCPDUMP_MAGIC &&
            fh.magic != FMESQUITA_TCPDUMP_MAGIC &&
            fh.magic != NAVTEL_TCPDUMP_MAGIC &&
            fh.magic != NSEC_TCPDUMP_MAGIC)
        {
            nethuns_perror(errbuf, "pcap_open: magic pcap_file_header mismatch!");
            fclose(f);
            return NULL;
        }

        ring = nethuns_make_ring(opt->numblocks * opt->numpackets, opt->packetsize);
        if (!ring)
        {
            nethuns_perror(errbuf, "pcap_open: failed to allocate ring");
            fclose(f);
            return NULL;
        }
    }
    else
    {
        snaplen = opt->packetsize;

        f = fopen(filename, "w");
        if (!f) {
            nethuns_perror(errbuf, "pcap_open");
            return NULL;
        }

        struct nethuns_pcap_file_header header =
        {
            .magic         = TCPDUMP_MAGIC
        ,   .version_major = 2
        ,   .version_minor = 4
        ,   .thiszone      = 0
        ,   .sigfigs       = 0
        ,   .snaplen       = 0xffff
        ,   .linktype      = 1 // DLT_EN10MB
        };

        if (fwrite (&header, sizeof(header), 1, f) != 1)
        {
            nethuns_perror(errbuf, "pcap_open: could not write to pcap file!");
            fclose(f);
            return NULL;
        }

        fflush(f);
    }

    pcap = malloc(sizeof(struct nethuns_pcap_socket));
    if (!pcap)
    {
        nethuns_perror(errbuf, "pcap_open: could not allocate socket");
        fclose(f);
        free(ring);
        return NULL;
    }

    pcap->base.opt  = *opt;
    pcap->file      = f;
    pcap->mode      = mode;
    pcap->snaplen   = snaplen;
    pcap->ring      = ring;
    pcap->idx       = 0;
    pcap->idx_rls   = 0;

    pcap->base.sync.number = 1;
    return pcap;
}


int
nethuns_pcap_close(nethuns_pcap_t *p)
{
    fclose(p->file);
    free(p->ring);
    free(p);
    return 0;
}


static int
__nethus_pcap_packets_release(nethuns_pcap_t *p)
{
    uint64_t rid = p->idx_rls, cur = UINT64_MAX;
    unsigned int i;

    for(i = 0; i < p->base.sync.number; i++)
        cur = MIN(cur, __atomic_load_n(&p->base.sync.id[i].value, __ATOMIC_ACQUIRE));

    for(; rid < cur; ++rid)
    {
        struct nethuns_ring_slot * slot = nethuns_ring_slot_mod(p->ring, rid);
        slot->inuse = 0;
    }

    p->idx_rls = rid;
    return 0;
}


uint64_t
nethuns_pcap_read(nethuns_pcap_t *p, nethuns_pkthdr_t **pkthdr, uint8_t **payload)
{
    unsigned int caplen = p->base.opt.packetsize;
    unsigned int bytes;
    size_t n;

    struct nethuns_pcap_pkthdr header;

    struct nethuns_ring_slot * slot = nethuns_ring_slot_mod(p->ring, p->idx);

    if (slot->inuse)
    {
        __nethus_pcap_packets_release(p);
        return 0;
    }

    if ((n = fread(&header, sizeof(header), 1, p->file)) != 1)
    {
        if (n)
            nethuns_perror(p->base.errbuf, "pcap_read: could not read packet hdr!");
        return  (uint64_t)-1;
    }

    bytes = MIN(caplen, header.caplen);

    if (fread(slot->packet, 1, bytes, p->file) != bytes)
    {
        nethuns_perror(p->base.errbuf, "pcap_read: could not read packet!");
        return (uint64_t)-1;
    }

    nethuns_tstamp_set_sec ((&slot->pkthdr), header.ts.tv_sec);
    nethuns_tstamp_set_usec((&slot->pkthdr), header.ts.tv_usec);

    nethuns_len        ((&slot->pkthdr)) = header.len;
    nethuns_snaplen    ((&slot->pkthdr)) = bytes;

    if (header.caplen > caplen)
    {
        long skip = header.caplen - caplen;
        if (fseek(p->file, skip, SEEK_CUR) < 0)
        {
            nethuns_perror(p->base.errbuf, "pcap_read: could not skip bytes!");
            return (uint64_t)-1;
        }
    }

    slot->inuse = 1;

    *pkthdr  = &slot->pkthdr;
    *payload =  slot->packet;

    p->idx++;

    return p->idx;
}


int
nethuns_pcap_write(nethuns_pcap_t *s, nethuns_pkthdr_t *pkthdr, uint8_t const *packet, unsigned int len)
{
    struct nethuns_pcap_pkthdr header;

    header.ts.tv_sec  = nethuns_tstamp_get_sec(pkthdr);
    header.ts.tv_usec = nethuns_tstamp_get_usec(pkthdr);
    header.caplen     = (uint32_t) MIN(len, nethuns_snaplen(pkthdr));
    header.len        = (uint32_t) nethuns_len(pkthdr);

    fwrite(&header, sizeof(header), 1, s->file);
    fwrite(packet, 1, header.caplen, s->file);
    fflush(s->file);
    return 0;
}



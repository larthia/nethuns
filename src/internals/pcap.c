#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

#include "internals/stub.h"

#include "pcap.h"

#define TCPDUMP_MAGIC		    0xa1b2c3d4
#define KUZNETZOV_TCPDUMP_MAGIC	0xa1b2cd34
#define FMESQUITA_TCPDUMP_MAGIC	0xa1b234cd
#define NAVTEL_TCPDUMP_MAGIC	0xa12b3c4d
#define NSEC_TCPDUMP_MAGIC	    0xa1b23c4d


nethuns_pcap_t *
nethuns_pcap_open(struct nethuns_socket_options *opt, const char *filename, int mode)
{
    struct nethuns_pcap_socket *pcap;
    FILE *f;
    void *ring;
    uint32_t snaplen;

    if (!mode)
    {
        f = fopen(filename, "r");
        if (!f) {
            perror("nethuns_pcap_open");
            return NULL;
        }

        struct nethuns_pcap_file_header fh;
        if (fread(&fh, sizeof(fh), 1, f) != 1)
        {
            perror("nethuns_pcap_open: could not read pcap_file_header");
            fclose(f);
            return NULL;
        }

        snaplen = fh.snaplen;

        if (fh.magic != TCPDUMP_MAGIC &&
            fh.magic != KUZNETZOV_TCPDUMP_MAGIC	&&
            fh.magic != FMESQUITA_TCPDUMP_MAGIC	&&
            fh.magic != NAVTEL_TCPDUMP_MAGIC &&
            fh.magic != NSEC_TCPDUMP_MAGIC)
        {
            perror("nethuns_pcap_open: magic pcap_file_header mismatch!");
            fclose(f);
            return NULL;
        }
    }
    else
    {
        f = fopen(filename, "w");
        if (!f) {
            perror("nethuns_pcap_open");
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
            perror("nethuns_pcap_open: could not write to pcap file!");
            fclose(f);
            return NULL;
        }

        fflush(f);
    }

    ring = calloc(1, opt->numblocks * opt->numpackets * (opt->packetsize + sizeof(struct nethuns_pcap_pkthdr)));
    if (!ring)
    {
        perror("nethuns_pcap_open: failed to allocate ring");
        fclose(f);
        return NULL;
    }

    pcap = malloc(sizeof(struct nethuns_pcap_socket));
    if (!pcap)
    {
        perror("nethuns_pcap_open: could not allocate socket");
        fclose(f);
        free(ring);
        return NULL;
    }

    pcap->opt       = *opt;
    pcap->file      = f;
    pcap->mode      = mode;
    pcap->snaplen   = snaplen;
    pcap->idx_p     = 0;
    pcap->idx_c     = 0;
    pcap->rx_ring   = ring;
    return pcap;
}


int
nethuns_pcap_close(nethuns_pcap_t *p)
{
    fclose(p->file);
    free(p->rx_ring);
    free(p);
    return 0;
}


uint64_t
nethuns_pcap_read(nethuns_pcap_t *p, nethuns_pkthdr_t **pkthdr, uint8_t **pkt)
{
    return 0;
}


int
nethuns_pcap_write(nethuns_pcap_t *s, nethuns_pkthdr_t *pkthdr, uint8_t const *packet, unsigned int len)
{
    struct nethuns_pcap_pkthdr header;

    header.ts.tv_sec  = nethuns_tstamp_sec(pkthdr);
    header.ts.tv_usec = nethuns_tstamp_nsec(pkthdr)/1000;
    header.caplen     = (uint32_t) MIN(len, nethuns_snaplen(pkthdr));
    header.len        = (uint32_t) nethuns_len(pkthdr);

    fwrite(&header, sizeof(header), 1, s->file);
    fwrite(packet, 1, header.caplen, s->file);
    fflush(s->file);
    return 0;
}



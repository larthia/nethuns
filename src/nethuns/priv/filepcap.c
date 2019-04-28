#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

#include "../nethuns.h"
#include "stub.h"
#include "compiler.h"

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

#ifdef NETHUNS_USE_NATIVE_FILEPCAP_READER
    FILE * pr = NULL;
#else
    pcap_t * pr = NULL;
#endif

    FILE *pw = NULL;

    size_t snaplen;

    if (opt->dir != nethuns_in_out)
    {
        nethuns_perror(errbuf, "unsupported catpure direction (%d)", (int)opt->dir);
        return NULL;
    }

    pcap = malloc(sizeof(struct nethuns_pcap_socket));
    if (!pcap)
    {
        nethuns_perror(errbuf, "pcap_open: could not allocate socket");
        return NULL;
    }

    if(nethuns_make_ring(opt->numblocks * opt->numpackets, opt->packetsize, &pcap->base.ring) < 0)
    {
        nethuns_perror(errbuf, "pcap_open: could not allocate ring");
        free(pcap);
        return NULL;
    }

    if (!mode)
    {
#ifndef NETHUNS_USE_NATIVE_FILEPCAP_READER
        char perr[PCAP_ERRBUF_SIZE];
        pr = pcap_open_offline(filename, perr);
        if (!pr) {
            nethuns_perror(errbuf, "pcap_open: could not open '%s' file", filename);
            free(pcap->base.ring.ring);
            free(pcap);
            return NULL;
        }

        snaplen = opt->packetsize;
#else
        pr = fopen(filename, "r");
        if (!pr) {
            nethuns_perror(errbuf, "pcap_open: could not open '%s' file", filename);
            free(pcap->base.ring.ring);
            free(pcap);
            return NULL;
        }

        struct nethuns_pcap_file_header fh;
        if (fread(&fh, sizeof(fh), 1, pr) != 1)
        {
            nethuns_perror(errbuf, "pcap_open: could not read pcap_file_header");
            fclose(pr);
            free(pcap->base.ring.ring);
            free(pcap);
            return NULL;
        }

        snaplen = MIN(fh.snaplen, opt->packetsize);

        if (fh.magic != TCPDUMP_MAGIC &&
            fh.magic != KUZNETZOV_TCPDUMP_MAGIC &&
            fh.magic != FMESQUITA_TCPDUMP_MAGIC &&
            fh.magic != NAVTEL_TCPDUMP_MAGIC &&
            fh.magic != NSEC_TCPDUMP_MAGIC)
        {
            nethuns_perror(errbuf, "pcap_open: magic pcap_file_header unsupported (%x)", fh.magic);
            fclose(pr);
            free(pcap->base.ring.ring);
            free(pcap);
            return NULL;
        }
#endif
    }
    else {

        pw = fopen(filename, "w");
        if (!pw) {
            nethuns_perror(errbuf, "pcap_open: could not open '%s' file for writing", filename);
            free(pcap->base.ring.ring);
            free(pcap);
            return NULL;
        }

        snaplen = opt->packetsize;

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

        if (fwrite (&header, sizeof(header), 1, pw) != 1)
        {
            nethuns_perror(errbuf, "pcap_open: could not write to pcap file!");
            fclose(pw);
            free(pcap->base.ring.ring);
            free(pcap);
            return NULL;
        }

        fflush(pw);
    }

    pcap->base.opt  = *opt;
    pcap->r         = pr;
    pcap->w         = pw;
    pcap->snaplen   = snaplen;
    return pcap;
}


int
nethuns_pcap_close(nethuns_pcap_t *p)
{
    if (p->r) {
#ifdef NETHUNS_USE_NATIVE_FILEPCAP_READER
        fclose(p->r);
#else
        pcap_close(p->r);
#endif
    }

    if (p->w) {
        fclose(p->w);
    }

    free(p->base.ring.ring);
    free(p);
    return 0;
}


#ifndef NETHUNS_USE_NATIVE_FILEPCAP_READER
uint64_t
nethuns_pcap_read(nethuns_pcap_t *p, nethuns_pkthdr_t const **pkthdr, uint8_t const **payload)
{
    unsigned int caplen = p->base.opt.packetsize;
    unsigned int bytes;

    struct pcap_pkthdr header;

    struct nethuns_ring_slot * slot = nethuns_get_ring_slot(&p->base.ring, p->base.ring.head);

#if 1
    if (__atomic_load_n(&slot->inuse, __ATOMIC_ACQUIRE))
    {
        return 0;
    }
#else
    if ((p->base.ring.head - p->base.ring.tail) == (p->base.ring.size-1))
    {
        nethuns_ring_free_id(&p->base.ring, nethuns_pcap_free_id, NULL);
        if ((p->base.ring.head - p->base.ring.tail) == (p->base.ring.size-1))
            return 0;
    }
#endif

    const unsigned char *ppkt = pcap_next(p->r, &header);
    if (ppkt == NULL) {
        nethuns_perror(p->base.errbuf, "pcap_read: could not read packet!");
        return  (uint64_t)-1;
    }

    bytes = MIN(caplen, header.caplen);

    nethuns_tstamp_set_sec ((&slot->pkthdr), header.ts.tv_sec);
    nethuns_tstamp_set_usec((&slot->pkthdr), header.ts.tv_usec);

    nethuns_set_len (&slot->pkthdr, header.len);
    nethuns_set_snaplen (&slot->pkthdr, bytes);

    memcpy(slot->packet, ppkt, bytes);

    __atomic_store_n(&slot->inuse, 1, __ATOMIC_RELEASE);

    *pkthdr   = &slot->pkthdr;
    *payload  =  slot->packet;

    return ++p->base.ring.head;
}
#else
uint64_t
nethuns_pcap_read(nethuns_pcap_t *p, nethuns_pkthdr_t const **pkthdr, uint8_t const **payload)
{
    unsigned int caplen = p->base.opt.packetsize;
    unsigned int bytes;
    size_t n;

    struct nethuns_pcap_pkthdr header;

    struct nethuns_ring_slot * slot = nethuns_get_ring_slot(&p->base.ring, p->base.ring.head);

#if 1
    if (__atomic_load_n(&slot->inuse, __ATOMIC_ACQUIRE))
    {
        return 0;
    }
#else
    if ((p->base.ring.head - p->base.ring.tail) == (p->base.ring.size-1))
    {
        nethuns_ring_free_id(&p->base.ring, nethuns_pcap_free_id, NULL);
        if ((p->base.ring.head - p->base.ring.tail) == (p->base.ring.size-1))
            return 0;
    }
#endif

    if ((n = fread(&header, sizeof(header), 1, p->r)) != 1)
    {
        if (n)
            nethuns_perror(p->base.errbuf, "pcap_read: could not read packet hdr!");
        return  (uint64_t)-1;
    }

    bytes = MIN(caplen, header.caplen);

    if (fread(slot->packet, 1, bytes, p->r) != bytes)
    {
        nethuns_perror(p->base.errbuf, "pcap_read: could not read packet!");
        return (uint64_t)-1;
    }

    nethuns_tstamp_set_sec ((&slot->pkthdr), header.ts.tv_sec);
    nethuns_tstamp_set_usec((&slot->pkthdr), header.ts.tv_usec);

    nethuns_set_len (&slot->pkthdr, header.len);
    nethuns_set_snaplen (&slot->pkthdr, bytes);

    if (header.caplen > caplen)
    {
        long skip = header.caplen - caplen;
        if (fseek(p->r, skip, SEEK_CUR) < 0)
        {
            nethuns_perror(p->base.errbuf, "pcap_read: could not skip bytes!");
            return (uint64_t)-1;
        }
    }

    __atomic_store_n(&slot->inuse, 1, __ATOMIC_RELEASE);

    *pkthdr   = &slot->pkthdr;
    *payload  =  slot->packet;

    return ++p->base.ring.head;
}

#endif

int
nethuns_pcap_write(nethuns_pcap_t *s, nethuns_pkthdr_t const *pkthdr, uint8_t const *packet, unsigned int len)
{
    struct nethuns_pcap_pkthdr header;
    int has_vlan_offload = nethuns_offvlan_tpid(pkthdr) ? 1 : 0;

    header.ts.tv_sec  = nethuns_tstamp_sec(pkthdr);
    header.ts.tv_usec = nethuns_tstamp_usec(pkthdr);

    header.caplen     = (uint32_t) MIN(len, (nethuns_snaplen(pkthdr) + 4 * has_vlan_offload));
    header.len        = (uint32_t) (nethuns_len(pkthdr) + 4 * has_vlan_offload);

    fwrite(&header, sizeof(header), 1, s->w);

    if (has_vlan_offload)
    {
        uint16_t h8021q[2] = { htons(nethuns_offvlan_tpid(pkthdr)), htons(nethuns_offvlan_tci(pkthdr)) };
        fwrite(packet,    1, 12, s->w);
        fwrite(h8021q,    1, 4,  s->w);
        fwrite(packet+12, 1, header.caplen-16, s->w);
    }
    else
    {
        fwrite(packet, 1, header.caplen, s->w);
    }

    fflush(s->w);
    return 0;
}



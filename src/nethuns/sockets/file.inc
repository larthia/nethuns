#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <time.h>
#include <string.h>

#ifndef NETHUNS_USE_BUILTIN_PCAP_READER
#include <pcap/pcap.h>
#endif

#include "../misc/compiler.h"
#include "../misc/macro.h"
#include "../sockets/ring.h"
#include "../api.h"
#include "../stub.h"

#define TCPDUMP_MAGIC           0xa1b2c3d4
#define KUZNETZOV_TCPDUMP_MAGIC 0xa1b2cd34
#define FMESQUITA_TCPDUMP_MAGIC 0xa1b234cd
#define NAVTEL_TCPDUMP_MAGIC    0xa12b3c4d
#define NSEC_TCPDUMP_MAGIC      0xa1b23c4d

nethuns_pcap_t *
TEMPLATE(nethuns_pcap_open_,SOCKET_TYPE) (struct nethuns_socket_options *opt, const char *filename, int mode, char *errbuf)
{
    struct nethuns_socket_pcapfile *pcap;

#ifdef NETHUNS_USE_BUILTIN_PCAP_READER
    FILE * pr = NULL;
#else
    pcap_t * pr = NULL;
#endif

    size_t snaplen;

    if (opt->dir != nethuns_in_out)
    {
        nethuns_perror(errbuf, "pcap_open: unsupported catpure direction (%d)", (int)opt->dir);
        return NULL;
    }

    pcap = (struct nethuns_socket_pcapfile *)malloc(sizeof(struct nethuns_socket_pcapfile));
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
#ifndef NETHUNS_USE_BUILTIN_PCAP_READER
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
            fh.magic != NSEC_TCPDUMP_MAGIC)
        {
            nethuns_perror(errbuf, "pcap_open: magic pcap_file_header not supported (%x)", fh.magic);
            fclose(pr);
            free(pcap->base.ring.ring);
            free(pcap);
            return NULL;
        }

        pcap->magic = fh.magic;
#endif
    }
    else {

#ifdef NETHUNS_USE_BUILTIN_PCAP_READER
        pr = fopen(filename, "w");
        if (!pr) {
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

        if (fwrite (&header, sizeof(header), 1, pr) != 1)
        {
            nethuns_perror(errbuf, "pcap_open: could not write to pcap file!");
            fclose(pr);
            free(pcap->base.ring.ring);
            free(pcap);
            return NULL;
        }

        fflush(pr);
#else
        nethuns_perror(errbuf, "pcap_open: could not open pcap file for writing (use built-in pcap option)");
        free(pcap->base.ring.ring);
        free(pcap);
        return NULL;
#endif
    }

    pcap->base.opt  = *opt;
    pcap->r         = pr;
    pcap->snaplen   = snaplen;
    return pcap;
}


int 
TEMPLATE(nethuns_pcap_close_,SOCKET_TYPE) (nethuns_pcap_t *p)
{
    if (p->r) {
#ifdef NETHUNS_USE_BUILTIN_PCAP_READER
        fclose(p->r);
#else
        pcap_close(p->r);
#endif
    }

    free(p->base.ring.ring);
    free(p);
    return 0;
}


uint64_t
TEMPLATE(nethuns_pcap_read_,SOCKET_TYPE) (nethuns_pcap_t *p, nethuns_pkthdr_t const **pkthdr, uint8_t const **payload)
#ifndef NETHUNS_USE_BUILTIN_PCAP_READER
{
    unsigned int caplen = p->base.opt.packetsize;
    unsigned int bytes;

    struct nethuns_ring_slot * slot = nethuns_ring_get_slot(&p->base.ring, p->base.ring.head);

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
    struct pcap_pkthdr *pcaphdr;

    const unsigned char *ppkt;
    int ret = pcap_next_ex(p->r, &pcaphdr, &ppkt);
    switch(ret)
    {
    case 0: return 0;
    case PCAP_ERROR: {
        nethuns_perror(p->base.errbuf, "pcap_next: could not read packet (%s)", pcap_geterr(p->r));
        return  NETHUNS_ERROR;
    }
    case PCAP_ERROR_BREAK: {
        return NETHUNS_EOF;
    }
    }

    bytes = MIN(caplen, pcaphdr->caplen);

    nethuns_tstamp_set_sec ((&slot->pkthdr), pcaphdr->ts.tv_sec);
    if (p->magic == NSEC_TCPDUMP_MAGIC) {
        nethuns_tstamp_set_nsec((&slot->pkthdr), pcaphdr->ts.tv_usec);
    }
    else {
        nethuns_tstamp_set_usec((&slot->pkthdr), pcaphdr->ts.tv_usec);
    }

    nethuns_set_len (&slot->pkthdr, pcaphdr->len);
    nethuns_set_snaplen (&slot->pkthdr, bytes);

    memcpy(slot->packet, ppkt, bytes);

    __atomic_store_n(&slot->inuse, 1, __ATOMIC_RELEASE);

    *pkthdr   = &slot->pkthdr;
    *payload  =  slot->packet;

    return ++p->base.ring.head;
}
#else
{
    unsigned int caplen = p->base.opt.packetsize;
    unsigned int bytes;
    size_t n;

    struct nethuns_ring_slot * slot = nethuns_ring_get_slot(&p->base.ring, p->base.ring.head);
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

    struct nethuns_pcap_patched_pkthdr header;

    if ((n = fread(&header
                  , p->magic == KUZNETZOV_TCPDUMP_MAGIC ? sizeof(struct nethuns_pcap_patched_pkthdr) : sizeof(struct nethuns_pcap_pkthdr)
                  , 1
                  , p->r)) != 1)
    {
        if (feof(p->r)) {
            return NETHUNS_EOF;
        }

        nethuns_perror(p->base.errbuf, "pcap_read: could not read packet hdr!");
        return  NETHUNS_ERROR;
    }

    bytes = MIN(caplen, header.caplen);

    if (fread(slot->packet, 1, bytes, p->r) != bytes)
    {
        nethuns_perror(p->base.errbuf, "pcap_read: could not read packet!");
        return  NETHUNS_ERROR;
    }

    nethuns_tstamp_set_sec ((&slot->pkthdr), header.ts.tv_sec);

    if (p->magic == NSEC_TCPDUMP_MAGIC) {
        nethuns_tstamp_set_nsec((&slot->pkthdr), header.ts.tv_usec);
    }
    else {
        nethuns_tstamp_set_usec((&slot->pkthdr), header.ts.tv_usec);
    }

    nethuns_set_len (&slot->pkthdr, header.len);
    nethuns_set_snaplen (&slot->pkthdr, bytes);

    if (header.caplen > caplen)
    {
        long skip = header.caplen - caplen;
        if (fseek(p->r, skip, SEEK_CUR) < 0)
        {
            nethuns_perror(p->base.errbuf, "pcap_read: could not skip bytes!");
            return  NETHUNS_ERROR;
        }
    }

    __atomic_store_n(&slot->inuse, 1, __ATOMIC_RELEASE);

    *pkthdr   = &slot->pkthdr;
    *payload  =  slot->packet;

    return ++p->base.ring.head;
}
#endif

int
TEMPLATE(nethuns_pcap_write_,SOCKET_TYPE) (nethuns_pcap_t *s, struct nethuns_pcap_pkthdr const *header, uint8_t const *packet, unsigned int len)
#ifdef NETHUNS_USE_BUILTIN_PCAP_READER
{
    fwrite(header, sizeof(struct nethuns_pcap_pkthdr), 1, s->r);
    if (fwrite(packet, 1, len, s->r) != len) {
        return -1;
    }
    fflush(s->r);
    return len;
}
#else
{
    (void)s;
    (void)header;
    (void)packet;
    (void)len;
    return -1;
}
#endif


int
TEMPLATE(nethuns_pcap_store_,SOCKET_TYPE) (nethuns_pcap_t *s, nethuns_pkthdr_t const *pkthdr, uint8_t const *packet, unsigned int len)
#ifdef NETHUNS_USE_BUILTIN_PCAP_READER
{
    struct nethuns_pcap_pkthdr header;
    int has_vlan_offload = nethuns_offvlan_tpid(pkthdr) ? 1 : 0;

    header.ts.tv_sec  = nethuns_tstamp_sec(pkthdr);
    header.ts.tv_usec = nethuns_tstamp_usec(pkthdr);

    header.caplen     = (uint32_t) MIN(len, (nethuns_snaplen(pkthdr) + 4 * has_vlan_offload));
    header.len        = (uint32_t) (nethuns_len(pkthdr) + 4 * has_vlan_offload);

    fwrite(&header, sizeof(header), 1, s->r);

    uint32_t clen = header.caplen;

    if (has_vlan_offload)
    {
        uint16_t h8021q[2] = { htons(nethuns_offvlan_tpid(pkthdr)), htons(nethuns_offvlan_tci(pkthdr)) };
        fwrite(packet,    1, 12, s->r);
        fwrite(h8021q,    1, 4,  s->r);
        clen = header.caplen-16;
        if (fwrite(packet+12, 1, clen, s->r) != clen) {
            return -1;
        }
    }
    else
    {
        if (fwrite(packet, 1, header.caplen, s->r) != header.caplen) {
            return -1;
        }
    }

    fflush(s->r);
    return clen;
}
#else
{
    (void)s;
    (void)pkthdr;
    (void)packet;
    (void)len;
    return -1;
}
#endif


int 
TEMPLATE(nethuns_pcap_rewind_,SOCKET_TYPE) (nethuns_pcap_t *s)
#ifdef NETHUNS_USE_BUILTIN_PCAP_READER
{
    return fseek(s->r, sizeof(struct nethuns_pcap_file_header), SEEK_SET);
}
#else
{
    (void)s;
    return -1;
}
#endif

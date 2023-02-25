#include <nethuns/nethuns.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/if_ether.h>
#ifdef __linux__
#include <netinet/ether.h>
#else
#include <net/ethernet.h>
#endif

#include <ctype.h>
#include <sys/time.h>
#include <sys/param.h>

#ifdef __APPLE__

char *
ether_ntoa_r(const struct ether_addr *addr, char *buf)
{
    static const char lookup[] = "0123456789abcdef";
    unsigned long x = 0U;
    for(unsigned long i = 0; i < sizeof(addr->octet); i++)
    {
        buf[x++] = lookup[addr->octet[i] >> 4];
        buf[x++] = lookup[addr->octet[i] & 0xf];
        if (i < (sizeof(addr->octet)-1))
            buf[x++]= ':';
    }
    buf[x] = '\0';
    return buf;
}
#endif


const char *
print_timestamp(uint32_t sec, uint32_t nsec) {
    static char timestr[64];
    struct timeval tv;
    tv.tv_sec = sec;
    tv.tv_usec = nsec/ 1000;
    time_t t = (time_t)tv.tv_sec;
    strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", gmtime(&t));
    snprintf(timestr + strlen(timestr), sizeof(timestr) - strlen(timestr), ".%06d", (int)tv.tv_usec);
    return timestr;
}


const char*
print_tcpflags(struct tcphdr* tcp, char* buf) {
    int pos = 0;

    if (tcp->th_flags & TH_FIN) {
        buf[pos++] = 'F';
    }

    if (tcp->th_flags & TH_SYN) {
        buf[pos++] = 'S';
    }

    if (tcp->th_flags & TH_RST) {
        buf[pos++] = 'R';
    }

    if (tcp->th_flags & TH_PUSH) {
        buf[pos++] = 'P';
    }

    if (tcp->th_flags & TH_ACK) {
        buf[pos++] = 'A';
    }

    if (tcp->th_flags & TH_URG) {
        buf[pos++] = 'U';
    }

    buf[pos] = '\0';
    return buf;
}


uint16_t
get_ethertype(const uint8_t* frame, uint16_t length) {
    if (length < 14) {  // Not enough bytes for standard Ethernet header
        return 0;
    }
    uint16_t ethertype = ((uint16_t)frame[12] << 8) | (uint16_t)frame[13];
    if (ethertype == 0x8100) {  // VLAN tag present
        if (length < 18) {  // Not enough bytes for VLAN tag and EtherType
            return 0;
        }
        ethertype = ((uint16_t)frame[16] << 8) | (uint16_t)frame[17];
    }
    return ethertype;
}


void
dump_ip_packet(uint32_t vlan_offset, nethuns_pkthdr_t const *hdr, const unsigned char *frame)
{
    char ip4_src[INET_ADDRSTRLEN];
    char ip4_dst[INET_ADDRSTRLEN];

    uint32_t i = 0;

    struct ip *ip_hdr = (struct ip *)(frame + sizeof(struct ether_header) + vlan_offset);
    uint32_t ip_hdr_len = ip_hdr->ip_hl * 4;
    if (ip_hdr->ip_v == 4 && ip_hdr_len >= 20 && ip_hdr_len <= (nethuns_len(hdr) - sizeof(struct ether_header) + vlan_offset))
    {
        inet_ntop(AF_INET, &ip_hdr->ip_src, ip4_src, sizeof(ip4_src));
        inet_ntop(AF_INET, &ip_hdr->ip_dst, ip4_dst, sizeof(ip4_dst));

        // TCP header
        if (ip_hdr->ip_p == IPPROTO_TCP)
        {
            struct tcphdr *tcp_hdr = (struct tcphdr *)(frame + sizeof(struct ether_header) + vlan_offset + ip_hdr_len);
            int tcp_hdr_len = tcp_hdr->th_off * 4;
            if (tcp_hdr_len >= 20 && ip_hdr_len + tcp_hdr_len <= nethuns_len(hdr) - (sizeof(struct ether_header)+ vlan_offset))
            {
                char flags[8];
                printf("IP %s:%d > %s:%d TCP:%s\n", ip4_src, ntohs(tcp_hdr->th_sport), ip4_dst, ntohs(tcp_hdr->th_dport), print_tcpflags(tcp_hdr, flags));
            }
        }
        // UDP header
        else if (ip_hdr->ip_p == IPPROTO_UDP)
        {
            struct udphdr *udp_hdr = (struct udphdr *)(frame + sizeof(struct ether_header) + vlan_offset + ip_hdr_len);
            int udp_hdr_len = 8;
            if (udp_hdr_len >= 8 && ip_hdr_len + udp_hdr_len <= nethuns_len(hdr) - (sizeof(struct ether_header) + vlan_offset))
            {
                printf("IP %s:%d > %s:%d UDP\n", ip4_src, ntohs(udp_hdr->uh_sport), ip4_dst, ntohs(udp_hdr->uh_dport));
            }
        }
        // ICMP header
        else if (ip_hdr->ip_p == IPPROTO_ICMP)
        {
            struct icmp *icmp_hdr = (struct icmp *)(frame + sizeof(struct ether_header) + vlan_offset + ip_hdr_len);
            int icmp_hdr_len = 8;
            if (icmp_hdr_len >= 8 && ip_hdr_len + icmp_hdr_len <= nethuns_len(hdr) - (sizeof(struct ether_header) + vlan_offset))
            {
                printf("IP %s > %s ICMP type %d, code %d\n", ip4_src, ip4_dst, icmp_hdr->icmp_type, icmp_hdr->icmp_code);
            }
        }
        else
        {
            printf("IP %s > %s [ ", ip4_src, ip4_dst);
            for(; i < MIN(14, nethuns_len(hdr)); i++)
            {
                printf("%02x ", frame[i]);
            }

            printf("]\n");
        }
    }  else {

       printf("IP (truncated)\n");
    }
}


void
dump_ip6_packet(uint32_t vlan_offset, nethuns_pkthdr_t const *hdr, const unsigned char *frame)
{
    char ip6_src[INET6_ADDRSTRLEN];
    char ip6_dst[INET6_ADDRSTRLEN];

    uint32_t i = 0;

    struct ip6_hdr *ipv6_hdr = (struct ip6_hdr *)(frame + sizeof(struct ether_header) + vlan_offset);
    uint32_t ipv6_hdr_len = sizeof(struct ip6_hdr);
    if (ipv6_hdr_len <= (nethuns_len(hdr) - sizeof(struct ether_header) + vlan_offset))
    {
        inet_ntop(AF_INET6, &ipv6_hdr->ip6_src, ip6_src, sizeof(ip6_src));
        inet_ntop(AF_INET6, &ipv6_hdr->ip6_dst, ip6_dst, sizeof(ip6_dst));

        // TCP header
        if (ipv6_hdr->ip6_nxt == IPPROTO_TCP)
        {
            struct tcphdr *tcp_hdr = (struct tcphdr *)(frame + sizeof(struct ether_header) + vlan_offset + ipv6_hdr_len);
            int tcp_hdr_len = tcp_hdr->th_off * 4;
            if (tcp_hdr_len >= 20 && ipv6_hdr_len + tcp_hdr_len <= nethuns_len(hdr) - (sizeof(struct ether_header)+ vlan_offset))
            {
                char flags[8];
                printf("IP6 %s:%d > %s:%d TCP:%s\n", ip6_src, ntohs(tcp_hdr->th_sport), ip6_dst, ntohs(tcp_hdr->th_dport), print_tcpflags(tcp_hdr, flags));
            }
        }
        // UDP header
        else if (ipv6_hdr->ip6_nxt == IPPROTO_UDP)
        {
            struct udphdr *udp_hdr = (struct udphdr *)(frame + sizeof(struct ether_header) + vlan_offset + ipv6_hdr_len);
            int udp_hdr_len = 8;
            if (udp_hdr_len >= 8 && ipv6_hdr_len + udp_hdr_len <= nethuns_len(hdr) - (sizeof(struct ether_header) + vlan_offset))
            {
                printf("IP6 %s:%d > %s:%d UDP\n", ip6_src, ntohs(udp_hdr->uh_sport), ip6_dst, ntohs(udp_hdr->uh_dport));
            }
        }
        // ICMPv6 header
        else if (ipv6_hdr->ip6_nxt == IPPROTO_ICMPV6)
        {
            struct icmp6_hdr *icmp6_hdr = (struct icmp6_hdr *)(frame + sizeof(struct ether_header) + vlan_offset + ipv6_hdr_len);
            int icmp6_hdr_len = 8;
            if (icmp6_hdr_len >= 8 && ipv6_hdr_len + icmp6_hdr_len <= nethuns_len(hdr) - (sizeof(struct ether_header) + vlan_offset)) {
                printf("IP6 %s > %s ICMPv6 type %d, code %d\n", ip6_src, ip6_dst, icmp6_hdr->icmp6_type, icmp6_hdr->icmp6_code);
            }

        } else {

            printf("IP6 %s > %s [ ", ip6_src, ip6_dst);
            for(; i < MIN(14, nethuns_len(hdr)); i++)
            {
                printf("%02x ", frame[i]);
            }

            printf("...]\n");
        }

    }  else {

       printf("IP6 (truncated)\n");
    }
}


void
dump_arp_packet(nethuns_pkthdr_t const *hdr, const unsigned char *frame) {
    if (nethuns_len(hdr) < sizeof(struct ether_arp)) {
        printf("ARP (truncated)\n");
        return;
    }

    char eth_src[20], eth_dst[20];

    struct ether_arp *arp_hdr = (struct ether_arp *)(frame + sizeof(struct ether_header));

    printf("ARP %s %s ", ((arp_hdr->ea_hdr.ar_op == htons(ARPOP_REQUEST)) ? "Request" : "Reply"),
        ether_ntoa_r((struct ether_addr *)arp_hdr->arp_tha, eth_src));

    printf("%d.%d.%d.%d > %d.%d.%d.%d",
        arp_hdr->arp_spa[0], arp_hdr->arp_spa[1], arp_hdr->arp_spa[2], arp_hdr->arp_spa[3],
        arp_hdr->arp_tpa[0], arp_hdr->arp_tpa[1], arp_hdr->arp_tpa[2], arp_hdr->arp_tpa[3]);

    printf(" at %s\n", ether_ntoa_r((struct ether_addr *)arp_hdr->arp_sha, eth_dst));
}


void
dump_packet(nethuns_pkthdr_t const *hdr, const unsigned char *frame, bool verbose)
{
    // non offloaded vlan offset, if any
    uint32_t vlan_offset = 0;
    if (nethuns_vlan_tci(frame) != 0)
    {
        vlan_offset = 4;
    }

    uint16_t etype = get_ethertype(frame, nethuns_len(hdr));

    switch (etype)
    {
        case 0x0800: {
            dump_ip_packet(vlan_offset, hdr, frame);
        } break;
        case 0x86dd: {
            dump_ip6_packet(vlan_offset, hdr, frame);
        } break;
        case 0x0806: {
            dump_arp_packet(hdr, frame);
        } break;
        default: {
            printf("ETHER TYPE 0x%x\n", etype);
        }
    }

    if (verbose)
    {
        uint32_t i = 0;

        for (i = 0; i < nethuns_len(hdr); i++)
        {
            if (i % 16 == 0 && i != 0)
            {
                printf(" ");
                for (int j = 0; j < 16; j++)
                {
                    if (i + j < nethuns_len(hdr))
                    {
                        printf("%c", isprint(frame[i+j]) ? frame[i+j] : '.');
                    }
                    else
                    {
                        printf(" ");
                    }
                }
                printf("\n");
            }
            printf("%02x ", frame[i]);
        }
        printf("\n");
    }
}


void
dump_frame(nethuns_pkthdr_t const *hdr, const unsigned char *frame, bool verbose)
{
    const char *tstamp = print_timestamp(nethuns_tstamp_sec(hdr), nethuns_tstamp_nsec(hdr));
    char rxhash[24];

    if (nethuns_rxhash(hdr)) {
        snprintf(rxhash, sizeof(rxhash), "rxhash:0x%x ", nethuns_rxhash(hdr));
    } else {
        rxhash[0] ='\0';
    }

    if (nethuns_vlan_tpid_(hdr, frame)) {

        printf("%s len:%u/%u [tci:%x tpid:%x vid:%d] %s", tstamp
                                                             , nethuns_snaplen(hdr)
                                                             , nethuns_len(hdr)
                                                             , nethuns_vlan_tci_(hdr, frame)
                                                             , nethuns_vlan_tpid_(hdr, frame)
                                                             , nethuns_vlan_vid(nethuns_vlan_tci_(hdr, frame))
                                                             , rxhash);

    } else {

        printf("%s len:%u/%u %s", tstamp
                                     , nethuns_snaplen(hdr)
                                     , nethuns_len(hdr)
                                     , rxhash);
    }

    dump_packet(hdr, frame, verbose);
}

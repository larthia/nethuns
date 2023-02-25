#include <nethuns/nethuns.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#include <ctype.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <sys/time.h>
#include <sys/param.h>

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

void dump_parsed_packet(nethuns_pkthdr_t const *hdr, const unsigned char *frame, bool verbose)
{
    uint32_t i = 0;

    // non offloaded vlan offset, if any
    uint32_t vlan_offset = 0;
    if (nethuns_vlan_tci(frame) != 0)
    {
        vlan_offset = 4;
    }

    // IP header
    struct ip *ip_hdr = (struct ip *)(frame + sizeof(struct ether_header) + vlan_offset);
    uint32_t ip_hdr_len = ip_hdr->ip_hl * 4;
    if (ip_hdr->ip_v == 4 && ip_hdr_len >= 20 && ip_hdr_len <= (nethuns_len(hdr) - sizeof(struct ether_header) + vlan_offset))
    {
        printf("IP: %s -> %s: ", inet_ntoa(ip_hdr->ip_src), inet_ntoa(ip_hdr->ip_dst));

        // TCP header
        if (ip_hdr->ip_p == IPPROTO_TCP)
        {
            struct tcphdr *tcp_hdr = (struct tcphdr *)(frame + sizeof(struct ether_header) + vlan_offset + ip_hdr_len);
            int tcp_hdr_len = tcp_hdr->th_off * 4;
            if (tcp_hdr_len >= 20 && ip_hdr_len + tcp_hdr_len <= nethuns_len(hdr) - (sizeof(struct ether_header)+ vlan_offset))
            {
                printf("TCP: %d -> %d\n", ntohs(tcp_hdr->th_sport), ntohs(tcp_hdr->th_dport));
            }
        }
        // UDP header
        else if (ip_hdr->ip_p == IPPROTO_UDP)
        {
            struct udphdr *udp_hdr = (struct udphdr *)(frame + sizeof(struct ether_header) + vlan_offset + ip_hdr_len);
            int udp_hdr_len = 8;
            if (udp_hdr_len >= 8 && ip_hdr_len + udp_hdr_len <= nethuns_len(hdr) - (sizeof(struct ether_header) + vlan_offset))
            {
                printf("UDP: %d -> %d\n", ntohs(udp_hdr->uh_sport), ntohs(udp_hdr->uh_dport));
            }
        }

        // ICMP header
        else if (ip_hdr->ip_p == IPPROTO_ICMP)
        {
            struct icmp *icmp_hdr = (struct icmp *)(frame + sizeof(struct ether_header) + vlan_offset + ip_hdr_len);
            int icmp_hdr_len = 8;
            if (icmp_hdr_len >= 8 && ip_hdr_len + icmp_hdr_len <= nethuns_len(hdr) - (sizeof(struct ether_header) + vlan_offset))
            {
                printf("ICMP: type %d, code %d\n", icmp_hdr->icmp_type, icmp_hdr->icmp_code);
            }
        }
        else
        {
            for(; i < MIN(14, nethuns_len(hdr)); i++)
            {
                printf("%02x ", frame[i]);
            }

            printf("\n");
        }

    } else {
        printf("Non IPv4 packet\n");
    }

    if (verbose)
    {
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


void dump_packet(nethuns_pkthdr_t const *hdr, const unsigned char *frame, bool verbose)
{
    const char *tstamp = print_timestamp(nethuns_tstamp_sec(hdr), nethuns_tstamp_nsec(hdr));

    printf("%s [%u:%u] snap:%u len:%u [tci:%x tpid:%x vid:%d] rxhash:0x%x > ", tstamp, nethuns_tstamp_sec(hdr)
                                                                            , nethuns_tstamp_nsec(hdr)
                                                                            , nethuns_snaplen(hdr)
                                                                            , nethuns_len(hdr)
                                                                            , nethuns_vlan_tci_(hdr, frame)
                                                                            , nethuns_vlan_tpid_(hdr, frame)
                                                                            , nethuns_vlan_vid(nethuns_vlan_tci_(hdr, frame))
                                                                            , nethuns_rxhash(hdr));

    dump_parsed_packet(hdr, frame, verbose);
}

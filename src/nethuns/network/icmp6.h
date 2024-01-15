#pragma once

#include <string.h>
#include <stdint.h>

enum icmp6_type
{
    ICMP6_DST_UNREACH                                   = 1,
    ICMP6_PACKET_TOO_BIG                                = 2,
    ICMP6_TIME_EXCEEDED                                 = 3,
    ICMP6_PARAM_PROB                                    = 4,
    ICMP6_ECHO_REQUEST                                  = 128,
    ICMP6_ECHO_REPLY                                    = 129,
    ICMP6_MLD_LISTENER_QUERY                            = 130,
    ICMP6_MLD_LISTENER_REPORT                           = 131,
    ICMP6_MLD_LISTENER_REDUCTION                        = 132,

    ICMP6_ROUTER_SOLICITATION                           = 133,
    ICMP6_ROUTER_ADVERTISEMENT                          = 134,
    ICMP6_NEIGHBOR_SOLICITATION                         = 135,
    ICMP6_NEIGHBOR_ADVERTISEMENT                        = 136,
    ICMP6_REDIRECT_MESSAGE                              = 137,
    ICMP6_ROUTER_RENUMBERING                            = 138,
    ICMP6_NODE_INFORMATION_QUERY                        = 139,
    ICMP6_NODE_INFORMATION_RESPONSE                     = 140,

    ICMP6_INVERSE_NEIGHBOR_DISCOVERY_SOLICITATION       = 141,
    ICMP6_INVERSE_NEIGHBOR_DISCOVERY_ADVERTISEMENT      = 142,
    ICMP6_MULTICAST_LISTENER_DISCOVERY_REPORTS          = 143,
    ICMP6_HOME_AGENT_ADDRESS_DISCOVERY_REQUEST          = 144,
    ICMP6_HOME_AGENT_ADDRESS_DISCOVERY_REPLY            = 145,
    ICMP6_MOBILE_PREFIX_SOLICITATION                    = 146,
    ICMP6_MOBILE_PREFIX_ADVERTISEMENT                   = 147,
    ICMP6_CERTIFICATION_PATH_SOLICITATION               = 148,
    ICMP6_CERTIFICATION_PATH_ADVERTISEMENT              = 149,
    ICMP6_EXPERIMENTAL_MOBILITY                         = 150,
    ICMP6_MULTICAST_ROUTER_ADVERTISEMENT                = 151,
    ICMP6_MULTICAST_ROUTER_SOLICITATION                 = 152,
    ICMP6_MULTICAST_ROUTER_TERMINATION                  = 153,
    ICMP6_FMIPV6                                        = 154,
    ICMP6_RPL_CONTROL_MESSAGE                           = 155,
    ICMP6_ILNPV6_LOCATOR_UPDATE                         = 156,
    ICMP6_DUPLICATE_ADDRESS_REQUEST                     = 157,
    ICMP6_DUPLICATE_ADDRESS_CONFIRM                     = 158,
    ICMP6_MPL_CONTROL_MESSAGE                           = 159,
    ICMP6_EXTENDED_ECHO_REQUEST                         = 160,
    ICMP6_EXTENDED_ECHO_REPLY                           = 161,
};

enum icmp6_code_unreach
{
    ICMP6_DST_UNREACH_NOROUTE                           = 0, /* no route to destination */
    ICMP6_DST_UNREACH_ADMIN                             = 1, /* communication with destination */
    ICMP6_DST_UNREACH_BEYONDSCOPE                       = 2, /* beyond scope of source address */
    ICMP6_DST_UNREACH_ADDR                              = 3, /* address unreachable */
    ICMP6_DST_UNREACH_NOPORT                            = 4 /* bad port */
};

enum icmp6_code_time_exceed
{
    ICMP6_TIME_EXCEED_TRANSIT                           = 0, /* Hop Limit == 0 in transit */
    ICMP6_TIME_EXCEED_REASSEMBLY                        = 1 /* Reassembly time out */
};

enum icmp6_param_prob
{
    ICMP6_PARAMPROB_HEADER                              = 0, /* erroneous header field */
    ICMP6_PARAMPROB_NEXTHEADER                          = 1, /* unrecognized Next Header */
    ICMP6_PARAMPROB_OPTION                              = 2 /* unrecognized IPv6 option */
};

struct icmp6_hdr
{
    icmp6_type  type;		/* message type */
    uint8_t     code;		/* type sub-code */
    uint16_t    checksum;

    union
    {
        uint32_t  data32[1]; /* type-specific field */
        uint16_t  data16[2]; /* type-specific field */
        uint8_t   data8[4];  /* type-specific field */
    } un;

} __attribute__((packed,aligned(4)));

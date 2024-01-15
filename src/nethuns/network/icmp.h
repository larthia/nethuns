#pragma once

#include <string.h>
#include <stdint.h>

enum icmp_type
{
    ICMP_ECHOREPLY		= 0	,   /* Echo Reply			    */
    ICMP_DEST_UNREACH	= 3	,   /* Destination Unreachable	*/
    ICMP_SOURCE_QUENCH	= 4	,   /* Source Quench		    */
    ICMP_REDIRECT		= 5	,   /* Redirect (change route)	*/
    ICMP_ECHO		    = 8	,   /* Echo Request			    */
    ICMP_ROUTER_ADV     = 9	,   /* Router ADV               */
    ICMP_ROUTER_SOLICIT = 10,   /* Router ADV               */
    ICMP_TIME_EXCEEDED	= 11,	/* Time Exceeded		    */
    ICMP_PARAMETERPROB	= 12,	/* Parameter Problem		*/
    ICMP_TIMESTAMP		= 13,	/* Timestamp Request		*/
    ICMP_TIMESTAMPREPLY	= 14,	/* Timestamp Reply		    */
    ICMP_INFO_REQUEST	= 15,	/* Information Request		*/
    ICMP_INFO_REPLY		= 16,	/* Information Reply		*/
    ICMP_ADDRESS		= 17,	/* Address Mask Request		*/
    ICMP_ADDRESSREPLY	= 18,	/* Address Mask Reply		*/
    ICMP_EX_ECHO        = 42,	/* Ex Echo                  */
    ICMP_EX_ECHOREPLY   = 43,	/* Ex Echo Reply            */
};

enum icmp_code_unreach
{
    ICMP_NET_UNREACH	= 0	,    /* Network Unreachable		*/
    ICMP_HOST_UNREACH	= 1	,    /* Host Unreachable		*/
    ICMP_PROT_UNREACH	= 2	,    /* Protocol Unreachable	*/
    ICMP_PORT_UNREACH	= 3	,    /* Port Unreachable		*/
    ICMP_FRAG_NEEDED	= 4	,    /* Fragmentation Needed/DF set	*/
    ICMP_SR_FAILED		= 5	,    /* Source Route failed		*/
    ICMP_NET_UNKNOWN	= 6 ,
    ICMP_HOST_UNKNOWN	= 7 ,
    ICMP_HOST_ISOLATED	= 8 ,
    ICMP_NET_ANO		= 9 ,
    ICMP_HOST_ANO		= 10,
    ICMP_NET_UNR_TOS	= 11,
    ICMP_HOST_UNR_TOS	= 12,
    ICMP_PKT_FILTERED	= 13,	/* Packet filtered */
    ICMP_PREC_VIOLATION	= 14,	/* Precedence violation */
    ICMP_PREC_CUTOFF	= 15	/* Precedence cut off */
};

enum icmp_code_redirect
{
    ICMP_REDIR_NET		= 0	,   /* Redirect Net			*/
    ICMP_REDIR_HOST		= 1	,   /* Redirect Host		*/
    ICMP_REDIR_NETTOS	= 2	,   /* Redirect Net for TOS		*/
    ICMP_REDIR_HOSTTOS	= 3	    /* Redirect Host for TOS	*/
};

enum icmp_code_time_exceed
{
    ICMP_EXC_TTL		= 0, 	/* TTL count exceeded		*/
    ICMP_EXC_FRAGTIME	= 1 	/* Fragment Reass time exceeded	*/
};


struct icmp_hdr
{
    icmp_type   type;		/* message type */
    uint8_t     code;		/* type sub-code */
    uint16_t    checksum;

    union
    {
        struct
        {
            uint16_t	id;
            uint16_t	sequence;
        } echo;			/* echo datagram */
        uint32_t	    gateway;	/* gateway address */
        struct
        {
            uint16_t	__glibc_reserved;
            uint16_t	mtu;
        } frag;			/* path mtu discovery */
    } un;
} __attribute__((packed,aligned(4)));

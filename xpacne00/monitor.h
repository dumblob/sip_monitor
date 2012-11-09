/*
 * Jan Pacner xpacne00@stud.fit.vutbr.cz
 * 2012-10-15 10:28:53 CEST
 */

#ifndef LOCAL_MONITOR_H
#define LOCAL_MONITOR_H

#include <stdint.h>  /* HACK for pcap missing u_int u_short etc. ( */
#define __USE_BSD    /*   needed under Linux)                      */
#include <pcap.h>

#include <netdb.h>  /* in_addr */
#include <stdint.h>  /* uintXX_t */
#include <regex.h>
#include "args.h"

#define RING_BUF_SIZE 8192  /* for 1 packet */
#define READ_TIMEOUT 300  /* ms */

#define IP_VERSION_4 4  /* was not able to figure out a portable way */
#define IP_VERSION_6 6  /* - || - */

#define MAX(x, y) (((x) > (y)) ? (x) : (y))

#define __ERE_ALPHANUM "[A-Za-z0-9]" //hotovo
#define __ERE_RESERVED "[;/?:@&=+$,]" //hotovo
#define __ERE_UNRESERVED "(" __ERE_ALPHANUM "|" __ERE_MARK ")"//hotovo
#define __ERE_ESCAPED "%[0-9A-Fa-f][0-9A-Fa-f]" //hotovo
//#define __ERE_TELEPHONE_SUBSCRIBER 
#define __ERE_PASSWORD "(" __ERE_UNRESERVED "|" __ERE_ESCAPED "|[&=+$,])*" //hotovo


#define __ERE_USER "(" __ERE_UNRESERVED "|" __ERE_ESCAPED "|[&=+$,;?/])+"
#define __ERE_USERINFO "(" __ERE_USER "|" __ERE_TELEPHONE_SUBSCRIBER ")(:" __ERE_PASSWORD ")?@" //hotovo


#define __ERE_PORT "[0-9]+"
#define __ERE_IPV4ADDRESS "[0-9]\{1,3\}[.][0-9]\{1,3\}[.][0-9]\{1,3\}[.][0-9]\{1,3\}"//hotovo
#define __ERE_HEXSEQ "[A-Fa-f0-9]\{1,4\}(:[A-Fa-f0-9]\{1,4\})*" //hotovo
#define __ERE_HEXPART "(" __ERE_HEXSEQ "|" __ERE_HEXSEQ "::(" __ERE_HEXSEQ ")?|::" __ERE_HEXSEQ ")" //hotovo
#define __ERE_IPV6REFERENCE "[[]" __ERE_HEXPART "(:" __ERE_IPV4ADDRESS ")?[]]"//hotovo
#define __ERE_HOSTNAME "([.])*([A-Za-z]|[A-Za-z](" __ERE_ALPHANUM "|-)*" __ERE_ALPHANUM ")" //hotovo
#define __ERE_HOSTPORT "(" __ERE_HOSTNAME "|" __ERE_IPV4ADDRESS "|" __ERE_IPV6REFERENCE ")(:" __ERE_PORT ")?"//hotovo


#define __ERE_SIP_URI "sips:(" __ERE_USERINFO ")?" __ERE_HOSTPORT __ERE_URI_PARAMETERS "(" __ERE_HEADERS ")?"//hotovo
#define __ERE_SIP_URI "sip:(" __ERE_USERINFO ")?" __ERE_HOSTPORT __ERE_URI_PARAMETERS "(" __ERE_HEADERS ")?"//hotovo
#define __ERE_SCHEME "[A-Za-z][A-Za-z0-9+-.]*" //hotovo
#define __ERE_HIER_PART "(" __ERE_NET_PATH "|" __ERE_ABS_PATH ")([?]" __ERE_QUERY ")?" //hotovo
#define __ERE_OPAQUE_PART "(" __ERE_RESERVED "|" __ERE_ESCAPED "|[;?:@&=+$,])(" __ERE_RESERVED "|" __ERE_UNRESERVED "|" __ERE_ESCAPED ")*" //hotovo
#define __ERE_ABSOLUTEURI __ERE_SCHEME ":(" __ERE_HIER_PART "|" __ERE_OPAQUE-PART ")" //hotovo
#define __ERE_TOKEN "([-.!%*_+`'~]|" __ERE_ALPHANUM ")+" //hotovo
#define __ERE_QUOTED_STRING "\"([^\"\\]*(\\.[^\"\\]*)*)\"" //hotovo
#define __ERE_ADDR_SPEC "(" __ERE_SIP_URI "|" __ERE_SIPS_URI "|" __ERE_ABSOLUTEURI ")"  //hotovo
#define __ERE_SIP_VERSION "SIP/[0-9]+[.][0-9]+"  //hotovo
#define ERE_SIP_INVITE "^INVITE " __ERE_REQUEST_URI " " __ERE_SIP_VERSION "$" //hotovo
//#define ERE_SIP_FROM   "^(From|f):(( ?" __ERE_TOKEN "( " __ERE_TOKEN ")*)| ?" __ERE_QUOTED_STRING ")? ?<" __ERE_ADDR_SPEC ">$"  //hotovo
#define ERE_SIP_FROM   "^(From|f):(( ?" __ERE_TOKEN "( " __ERE_TOKEN ")*)| ?" __ERE_QUOTED_STRING ")? ?<([^>])>$"  //hotovo
#define ERE_SIP_TO     "^To: (.*)$"
#define ERE_SIP_BYE    "^BYE (.*)$"
#define MAX_ERE_LEN MAX(MAX(MAX( \
          sizeof(ERE_SIP_FROM  ), \
          sizeof(ERE_SIP_TO    )), \
          sizeof(ERE_SIP_INVITE)), \
          sizeof(ERE_SIP_BYE   ))

typedef struct {
  /* one line of SIP message (though there is no limit in RFC) */
  uint8_t *line;
  regmatch_t pmatch[MAX_ERE_LEN];
  regex_t sip_from;
  regex_t sip_to;
  regex_t sip_invite;
  regex_t sip_bye;
} payload_mem_t;

/* ethernet frame */
typedef struct {
  /* preamble and frame delimiter are not part of pcap frame */
  uint8_t mac_addr_dst[6];
  uint8_t mac_addr_src[6];
  /* 802.1Q tag is removed by libpcap */
  uint16_t len_or_ethertype;  /* <1500 payload len
                                 >=1536 EtherType values
                                 rest is undefined */
  /* checksum is removed by libpcap */
} eth_hdr_t;

/* IPv4 header (according to RFC 791), partially adopted from tutorial
   http://www.tcpdump.org/pcap.html and
   http://systhread.net/texts/200805lpcap1.php) */
typedef struct {
  uint8_t        ver_hdrlen;      /* 4b version; 4b header length (in multiples of 4B) */
    #define IPv4_version(x) ((x) >> 4)  /* should be IPPROTO_IP */
    #define IPv4_hdrlen(x) (((x) & 0x0f) * 4)
  uint8_t        dscp;            /* differentiated services code point */
  uint16_t       totallen;        /* len of fragment (header + data) in bytes */
  uint16_t       id;              /* identification */
  uint16_t       flags_foff;      /* flags & fragment offset field */
    #define IPv4_DF       0x4000  /* dont fragment flag */
    #define IPv4_FOF_MASK 0x1fff  /* mask for fragmenting bits */
  uint8_t        ttl;
  uint8_t        proto;           /* protocol
                                     IPPROTO_IP (could be more than once,
                                       but we do not support IP in IP)
                                     IPPROTO_TCP
                                     IPPROTO_UDP */
  uint16_t       checksum;
  struct in_addr src;
  struct in_addr dst;
} ipv4_hdr_t;

/* IPv6 header (according to RFC 2460) */
typedef struct {
  uint32_t ver_class_label;  /* 4b version; 8b traffic class; 20b flow label */
    #define IPv6_version(x) ((x) >> (8 + 20))  /* should be IPPROTO_IPV6 */
  uint16_t payloadlen;  /* len of the data after current header in bytes */
  uint8_t nexthdr;  /* same as IPv4 protocol field
                       IPPROTO_NONE no next header
                       IPPROTO_IPV6 ipv6 header (can be more than once) */
  uint8_t hoplimit;
  struct in6_addr src;
  struct in6_addr dst;
} ipv6_hdr_t;

/* TCP header (according to RFC 793) */
typedef struct {
  uint16_t src;  /* port */
  uint16_t dst;  /* port */
  uint32_t seq;  /* sequence number */
  uint32_t acknum;  /* ack number */
  uint16_t len_res_con;  /* 4b len of TCP header in multiples of 4
                            6b reserved
                            6b control bits */
    #define TCP_hdrlen(x) (((x) & 0xf000) * 4)
  uint16_t window;
  uint16_t checksum;
  uint16_t urgent_ptr;
  uint32_t options;
} tcp_hdr_t;

/* UDP header (according to RFC 768) */
typedef struct {
  uint16_t src;  /* port */
  uint16_t dst;  /* port */
  uint16_t len;  /* len of (header + data) in bytes */
  uint16_t checksum;
} udp_hdr_t;

int start_sip_monitoring(args_s *);
void handle_packet(uint8_t *, const struct pcap_pkthdr *, const uint8_t *);
void handle_sip_data(payload_mem_t *, const uint8_t *, const uint32_t);

#endif

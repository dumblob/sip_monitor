/*
 * Jan Pacner xpacne00@stud.fit.vutbr.cz
 * 2012-10-15 10:28:53 CEST
 */

#ifndef LOCAL_MONITOR_H
#define LOCAL_MONITOR_H

#include <stdint.h>  /* HACK for pcap missing u_int u_short etc. ( */
#define __USE_BSD    /*   needed under Linux)                      */
#include <pcap/pcap.h>

//#include <netdb.h>
//#include <arpa/inet.h>  /* in_addr */

#include <stdint.h>  /* uintXX_t */
#include <netinet/in.h>  /* in_addr in6_addr */
#include <regex.h>
#include "args.h"
#include "list_sip.h"

#define RING_BUF_SIZE 8192  /* for 1 packet */
#define READ_TIMEOUT 300  /* ms */

/* not available on FreeBSD 8.1 stable */
#ifndef PCAP_NETMASK_UNKNOWN
#define PCAP_NETMASK_UNKNOWN 0xffffffff
#endif

#define IP_VERSION_4 4  /* content of the version field in IP header */
#define IP_VERSION_6 6  /* - || - */

#define MAX(x, y) (((x) > (y)) ? (x) : (y))

#define __ERE_SIP_VERSION "SIP/[0-9]+[.][0-9]+"
/* request-uri -> [^ ]+ */
#define ERE_SIP_INVITE      "^INVITE [^ ]+ " __ERE_SIP_VERSION "$"
#define ERE_SIP_CANCEL      "^CANCEL [^ ]+ " __ERE_SIP_VERSION "$"
#define ERE_SIP_BYE         "^BYE [^ ]+ "    __ERE_SIP_VERSION "$"
/* reason-phrase -> (.*) */
#define ERE_SIP_STATUS      "^" __ERE_SIP_VERSION " ([0-9]{3}) ?(.*)$"
#define ERE_SIP_STATUS_STATUS_I 1
#define ERE_SIP_STATUS_REASON_I 2

#define __ERE_TOKEN         "[-.!%*_+`'~A-Za-z0-9]+"
#define __ERE_QUOTED_STRING "\"([^\"\\]*(\\.[^\"\\]*)*)\""
/* addr-spec -> [^>]+ */
#define __ERE_SIP_FROM_TO_POSTFIX \
  "[ \t]*:[ \t]*((" __ERE_TOKEN "( " __ERE_TOKEN ")*|" __ERE_QUOTED_STRING ")[ \t]*)?<([^>]+)>.*$"
#define ERE_SIP_FROM "^(From|f)" __ERE_SIP_FROM_TO_POSTFIX
#define ERE_SIP_TO   "^(To|t)"   __ERE_SIP_FROM_TO_POSTFIX
#define ERE_SIP_FROM_TO_LABEL_I 5
#define ERE_SIP_FROM_TO_ADDR_I  7

/* word@word -> (.+) */
#define ERE_SIP_CALL_ID "^(Call-ID|i)[ \t]*:[ \t]*(.+)$"
#define ERE_SIP_CALL_ID_I 2

/* warning-value -> (.+) */
#define ERE_SIP_WARNING "^Warning[ \t]*:[ \t]*(.+)$"
#define ERE_SIP_WARNING_I 1

#define MAX_ERE_LEN MAX(MAX(MAX(MAX(MAX(MAX(MAX( \
                sizeof(ERE_SIP_INVITE ), \
                sizeof(ERE_SIP_CANCEL )), \
                sizeof(ERE_SIP_BYE    )), \
                sizeof(ERE_SIP_STATUS )), \
                sizeof(ERE_SIP_FROM   )), \
                sizeof(ERE_SIP_TO     )), \
                sizeof(ERE_SIP_CALL_ID)), \
                sizeof(ERE_SIP_WARNING))

/* package with allocated memory for passing through various functions */
typedef struct {
  args_s *args;
  /* one line of SIP message (though there is no limit in RFC) */
  char *line;
  regmatch_t pmatch[MAX_ERE_LEN];
  regex_t sip_invite;  /* must be on the first line */
  regex_t sip_cancel;  /* must be on the first line */
  regex_t sip_bye;     /* must be on the first line */
  regex_t sip_status;  /* must be on the first line */
  regex_t sip_from;
  regex_t sip_to;
  regex_t sip_call_id;
  regex_t sip_warning;
  list_sip_t *calls;
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
#ifdef DEBUG
void print_regex_parts(char *, regmatch_t *, int);
#endif
void print_duration(double);
void handle_sip_data(payload_mem_t *, const uint8_t *, const uint32_t);

#endif

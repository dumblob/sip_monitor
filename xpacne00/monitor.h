/*
 * Jan Pacner xpacne00@stud.fit.vutbr.cz
 * 2012-10-15 10:28:53 CEST
 */

#ifndef LOCAL_MONITOR_H
#define LOCAL_MONITOR_H

#include <netdb.h>  /* addrinfo FIXME*/
#include <stdint.h>  /* uintXX_t */
#include "args.h"

#define RING_BUF_SIZE 8192  /* for 1 packet */
#define READ_TIMEOUT 300  /* ms */

/* ethernet frame */
struct {
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
struct {
  uint8_t        ver_hdrlen;      /* 4b version; 4b header length (in multiples of 4B) */
    #define IPv4_version(x) ((x) >> 4)  /* should be IPPROTO_IP */
    #define IPv4_hdrlen(x) (((x) & 0x0f) * 4)
  uint8_t        dscp;            /* differentiated services code point */
  uint16_t       totallen;        /* len of fragment (header + data) in bytes */
  uint16_t       id;              /* identification */
  uint16_t       flagsfoff;       /* flags & fragment offset field */
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
struct {
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
struct {
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
struct {
  uint16_t src;  /* port */
  uint16_t dst;  /* port */
  uint16_t len;  /* len of (header + data) in bytes */
  uint16_t checksum;
} udp_hdr_t;

int start_sip_monitoring(args_s *);
void handle_packet(uint8_t *, const struct pcap_pkthdr *, const uint8_t *);
void handle_sip_data(uint8_t *, const uint8_t *, const uint32_t);

#endif

/*
 * Jan Pacner xpacne00@stud.fit.vutbr.cz
 * 2012-10-15 10:28:53 CEST
 */

#ifndef LOCAL_MONITOR_H
#define LOCAL_MONITOR_H

#include "args.h"

#define RING_BUF_SIZE 8192  /* for 1 packet */
#define READ_TIMEOUT 300  /* ms */

#define SIZE_ETHERNET 14  /* fixed ethernet header size */

/* IP header (adopted from tutorial on http://www.tcpdump.org/) */
struct {
  u_char      verhdrlen;       /* version << 4 | header length >> 2 */
  u_char      tos;             /* type of service */
  u_short     totallen;        /* total length */
  u_short     id;              /* identification */
  u_short     offfield;        /* fragment offset field */
    #define IP_RF      0x8000  /* reserved fragment flag */
    #define IP_DF      0x4000  /* dont fragment flag */
    #define IP_MF      0x2000  /* more fragments flag */
    #define IP_OFFMASK 0x1fff  /* mask for fragmenting bits */
  u_char      ttl;             /* time to live */
  u_char      proto;           /* protocol */
  u_short     checksum;        /* checksum */
  struct addr src;             /* source address */
  struct addr dst;             /* dest address */
} ipv4_hdr_t;

//FIXME doplnit
struct {
  u_char wtf;
} ipv6_hdr_t;

int start_sip_monitoring(args_s *);
void handle_packet(u_char *, const struct pcap_pkthdr *, const u_char *);

#endif

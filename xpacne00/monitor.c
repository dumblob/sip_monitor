/*
 * Jan Pacner xpacne00@stud.fit.vutbr.cz
 * 2012-10-15 10:28:53 CEST
 */

#include <stdint.h>  /* HACK for pcap missing u_int u_short etc. */
#define __USE_BSD    /*   needed under Linux                     */
#include <pcap.h>

#include <string.h>  /* memcpy */
#include <arpa/inet.h>  /* ntohs */
#include "common.h"
#include "args.h"
#include "monitor.h"

//FIXME
//{
//  fprintf(stderr, "ERR: %s \"%s\"\n", errbuf, args->i);
//  return EXIT_FAILURE;
//}

// libpcap
// prepnout do promiskuit
// pcap_datalink() ziska info o eth_int
//   --pcap_lookupdev() pripojeni k sitovemu rozhrani
//   pcap_open_live() pcap_open_offline() otevreni rozhrani pro cteni
//   pcap_dispatch() pcap_loop() pcap_next() cteni paketu
//   sam musim analyzovat paket

int start_sip_monitoring(args_s *args)
{
  char errbuf[PCAP_ERRBUF_SIZE];
  errbuf[0] = '\0';
  pcap_t *handle;

  //FIXME na freebsd asi pretypovat na (const char)
  //pcap_create(const char *source, char *errbuf)) == NULL)
  //if ((handle = pcap_create(args->i, errbuf)) == NULL)
  //{
  //  //printf("Unable to connect to device \"%s\"\n", args->i);
  //  fprintf(stderr, "ERR: %s\"%s\"\n", errbuf, args->i);
  //  return EXIT_FAILURE;
  //}

  //man pcap

  //pcap_findalldevs()  // return list of all capture devices (use to control allowed devices)
  //pcap_freealldevs()

  //1) set options to handle
  //  pcap_set_snaplen(N)  // get only first N bytes of packet
  //  pcap_set_promisc()
  //  ...
  //2) pcap_activate();
  //3) pcap_close()   // close the handle

  /* 1 promisc */
  if ((handle = pcap_open_live(args->i, RING_BUF_SIZE, 1, READ_TIMEOUT,
          errbuf)) == NULL)
  {
    fprintf(stderr, "ERR: %s \"%s\"\n", errbuf, args->i);
    return EXIT_FAILURE;
  }

  struct bpf_program filter;

  /* http://ethereal.cs.pu.edu.tw/lists/ethereal-users/200208/msg00039.html */
  if (pcap_compile(handle, &filter, "port 23", 1, PCAP_NETMASK_UNKNOWN))
  {
    fprintf(stderr, "ERR: %s \"%s\"\n", pcap_geterr(handle), args->i);
    return EXIT_FAILURE;
  }

  //FIXME man pcap-filter
  if (pcap_setfilter(handle, &filter))
  {
    fprintf(stderr, "ERR: %s \"%s\"\n", pcap_geterr(handle), args->i);
    return EXIT_FAILURE;
  }

  int ret = pcap_loop(handle, -1, handle_packet, (u_char *)NULL);
  pcap_close(handle);

  if (ret == -1)
  {
    fprintf(stderr, "ERR: %s \"%s\"\n", pcap_geterr(handle), args->i);
    return EXIT_FAILURE;
  }
  else
  {
    return EXIT_SUCCESS;
  }
}

void handle_packet(u_char *opts, const struct pcap_pkthdr *header,
    const u_char *packet)
{
  // FIXME ntohl??? net/ethernet.h ETHERTYPE_IPV6 ETHERTYPE_IP
  //ntohs(data->ether_type);

  /* define ethernet header */
  //ethernet = (struct sniff_ethernet *)packet;

  /* IPv4 header offset */
  ipv4_hdr_t *ip = (ipv4_hdr_t *)(packet + SIZE_ETHERNET);
  int size_ip = (ip->verhdrlen & 0x0f) * 4;  /* (first 4 bits) * (4B period) */
  int version_ip = ip->verhdrlen >> 4;  /* last 4 bits */

  if (size_ip < 20)
  {
    printf("Invalid IP header length: %u bytes\n", size_ip);
    return;
  }

  switch (ip->protocol)
  {
    case IPPROTO_UDP:
      printf("UDP yeah!\n");
      break;
    case IPPROTO_TCP:
    case IPPROTO_ICMP:
    case IPPROTO_IP:
    default:
      printf("bad protocol\n");
  }

  /* FIXME print source and destination IP addresses */
  printf("src: %s\n", inet_ntoa(ip->ip_src));
  printf("dst: %s\n", inet_ntoa(ip->ip_dst));

  //pcap_breakloop();

  printf("zpracovavam paket\n"); //FIXME debug
}

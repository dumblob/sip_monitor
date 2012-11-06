/*
 * Jan Pacner xpacne00@stud.fit.vutbr.cz
 * 2012-10-15 10:28:53 CEST
 */

#include <stdint.h>  /* HACK for pcap missing u_int u_short etc. ( */
#define __USE_BSD    /*   needed under Linux)                      */
#include <pcap.h>

#include <string.h>  /* memcpy */
#include <arpa/inet.h>  /* ntohs */
//#include <netinet/in.h>  /*FIXME ipv4/v6 structs */
//#include <netinet/if_ether.h>  /* FIXME ethernet struct */
#include "common.h"
#include "args.h"
#include "monitor.h"

// FIXME man pcap
// pcap_datalink() ziska info o eth_int
//   pcap_lookupdev() pripojeni k sitovemu rozhrani

/** monitor given device in promiscuitous mode using libpcap */
int start_sip_monitoring(args_s *args)
{
  char errbuf[PCAP_ERRBUF_SIZE];
  errbuf[0] = '\0';

  //FIXME cteni ze souboru
  //pcap_open_offline()
  /* 1 ~ promisc */
  if ((global_vars.handle = pcap_open_live(args->i, RING_BUF_SIZE, 1, READ_TIMEOUT,
          errbuf)) == NULL)
  {
    fprintf(stderr, "ERR: %s \"%s\"\n", errbuf, args->i);
    return EXIT_FAILURE;
  }

  struct bpf_program filter;

  /* IPv4, IPv6, TCP, UDP, port 5060
     http://ethereal.cs.pu.edu.tw/lists/ethereal-users/200208/msg00039.html */
  if (pcap_compile(global_vars.handle, &filter, "(tcp or udp) and (port 5060)", 1,
        PCAP_NETMASK_UNKNOWN))
  {
    fprintf(stderr, "ERR: %s \"%s\"\n", pcap_geterr(global_vars.handle), args->i);
    return EXIT_FAILURE;
  }

  /* man pcap-filter */
  if (pcap_setfilter(global_vars.handle, &filter))
  {
    fprintf(stderr, "ERR: %s \"%s\"\n", pcap_geterr(global_vars.handle), args->i);
    return EXIT_FAILURE;
  }

  /* one line of SIP message (though there is no limit in RFC) */
  uint8_t *buf;

  if ((buf = malloc(sizeof(uint8_t) * RING_BUF_SIZE)) == NULL)
    MALLOC_EXIT;

  int ret = pcap_loop(global_vars.handle, -1, global_vars.handle_packet, buf);
  pcap_close(global_vars.handle);
  free(buf);

  if (ret == -1)
  {
    fprintf(stderr, "ERR: %s \"%s\"\n", pcap_geterr(global_vars.handle), args->i);
    return EXIT_FAILURE;
  }
  else
  {
    return EXIT_SUCCESS;
  }
}

#define CHECK_PACKET_LEN \
  do { if (packet > _packet + header->caplen) return; } while (0)

/** remove packet headers (IPv4/v6, TCP/UDP) */
void handle_packet(uint8_t *buf, const struct pcap_pkthdr *header,
    const uint8_t *_packet)
{
  /* captured length */
  uint32_t cur_len = header->caplen; //FIXME bpf_u_int32
  uint8_t packet = _packet;

  /* jump over the ethernet header */
  cur_len -= sizeof(eth_hdr_t);
  packet  += sizeof(eth_hdr_t);
  CHECK_PACKET_LEN;

  bool tcp_found;

  /* jump over the IP header(s) */
  switch (IPv4_version(((ipv4_hdr_t *)packet)->verhdrlen))
  {
    case IPPROTO_IP:
      /* do not support fragmented packets (but if fragmented, take the
         first fragment and assume, the SIP message is not damaged */
      if (! (IPv4_DF ||
              (! (IPv4_FOF_MASK & ((ipv4_hdr_t *)packet)->flagsfoff))
            )
         ) return;

      switch (((ipv4_hdr_t *)packet)->proto)
      {
        case IPPROTO_TCP:
          tcp_found = true;
          break;
        case IPPROTO_UDP:
          tcp_found = false;
          break;
        default:
          return;
      }

      cur_len -= IPv4_hdrlen(((ipv4_hdr_t *)packet)->verhdrlen);
fprintf(stderr, "cur_len       %d\n"
                "ipv4 data len %d (MUST be the same as cur_len!)\n",
                cur_len,
                ntohs(((ipv4_hdr_t *)packet)->totallen)
                  - IPv4_hdrlen(((ipv4_hdr_t *)packet)->verhdrlen)); //FIXME debug
      packet +=  IPv4_hdrlen(((ipv4_hdr_t *)packet)->verhdrlen);
      CHECK_PACKET_LEN;

      break;

    case IPPROTO_IPV6:
      for (bool ipv6_hdr_found = false; ipv6_hdr_found; )
      {
        switch (((ipv6_hdr_t *)packet)->nexthdr)
        {
          case IPPROTO_TCP:
            tcp_found = true;
            break;
          case IPPROTO_UDP:
            tcp_found = false;
          case IPPROTO_IPV6:
            break;
          default:
            return;
        }

        cur_len -= sizeof(ipv6_hdr_t);
fprintf(stderr, "cur_len       %d\n"
                "ipv6 data len %d (MUST be the same as cur_len!)\n",
                cur_len,
                ((ipv6_hdr_t *)packet)->payloadlen); //FIXME debug
         packet  += sizeof(ipv6_hdr_t);
        CHECK_PACKET_LEN;
      }

      break;

    default:
      return;
  }

  /* jump over the TCP header */
  if (tcp_found)
  {
fprintf(stderr, "sizeof(tcp_hdr_t) %d\n"
                "TCP header len    %d (MUST be the same as cur_len!)\n",
                sizeof(tcp_hdr_t),
                TCP_hdrlen(((tcp_hdr_t *)packet)->len_res_con)); //FIXME debug
     cur_len -= sizeof(tcp_hdr_t);
    packet  += sizeof(tcp_hdr_t);
  }
  /* jump over the UDP header */
  else
  {
    cur_len -= sizeof(udp_hdr_t);
fprintf(stderr, "cur_len        %d\n"
                "UDP header len %d (MUST be the same as cur_len!)\n",
                cur_len,
                ntohs(((udp_hdr_t *)packet)->len_res_con)
                  - sizeof(udp_hdr_t)); //FIXME debug
    packet  += sizeof(udp_hdr_t);
  }

  CHECK_PACKET_LEN;

  /* FIXME print source and destination IP addresses */
  //printf("src: %s\n", inet_ntoa(ip->ip_src));
  //printf("dst: %s\n", inet_ntoa(ip->ip_dst));

  // FIXME handle_sip_data(packet, header->caplen - (packet - _packet));
  handle_sip_data(buf, packet, cur_len);
}

/** parse SIP data and print some of the extracted info */
void handle_sip_data(uint8_t *line, const uint8_t *data, const uint32_t len)
{
  //FIXME rtc start ulozit take do listu, v pripade ukonceni spojeni
  //  vycist z listu a podle toho vyresit tento problem :)
  //struct timespec ts_start;
  //clock_gettime(CLOCK_MONOTONIC, &ts_start);

  memcpy(line, data, len);
  line[len] = '\0';

  printf("SIP data of size %d:\n%sXXXX\n\n", len, line);
  fflush(stdout);
}

/*
 * Jan Pacner xpacne00@stud.fit.vutbr.cz
 * 2012-10-15 10:28:53 CEST
 */

#include <stdint.h>  /* HACK for pcap missing u_int u_short etc. ( */
#define __USE_BSD    /*   needed under Linux)                      */
#include <pcap.h>

#include <string.h>  /* memcpy */
#include <arpa/inet.h>  /* ntohs */
#include <stdbool.h>
#include <regex.h>
#include "common.h"
#include "args.h"
#include "monitor.h"

extern struct global_vars_s global_vars;

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
  if (pcap_compile(global_vars.handle, &filter,
        "(tcp || udp) && (port 5060)", 1, PCAP_NETMASK_UNKNOWN))
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

  payload_mem_t mem;

  if ((mem.line = malloc(sizeof(uint8_t) * RING_BUF_SIZE)) == NULL)
    MALLOC_EXIT;
  memset((void *)mem.pmatch, 0, MAX_ERE_LEN);
  if (regcomp(&mem.sip_from,   ERE_SIP_FROM,   REG_EXTENDED)) REGCOMP_EXIT;
  if (regcomp(&mem.sip_to,     ERE_SIP_TO,     REG_EXTENDED)) REGCOMP_EXIT;
  if (regcomp(&mem.sip_invite, ERE_SIP_INVITE, REG_EXTENDED)) REGCOMP_EXIT;
  if (regcomp(&mem.sip_bye,    ERE_SIP_BYE,    REG_EXTENDED)) REGCOMP_EXIT;

  int ret = pcap_loop(global_vars.handle, -1, handle_packet, (void *)&mem);

  pcap_close(global_vars.handle);
  free(mem.line);
  regfree(&mem.sip_from);
  regfree(&mem.sip_to);
  regfree(&mem.sip_invite);
  regfree(&mem.sip_bye);

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
void handle_packet(uint8_t *mem, const struct pcap_pkthdr *header,
    const uint8_t *_packet)
{
  /* captured length */
  uint32_t cur_len = header->caplen;
  uint8_t *packet = (uint8_t *)_packet;

  /* jump over the ethernet header */
  cur_len -= sizeof(eth_hdr_t);
  packet  += sizeof(eth_hdr_t);
  CHECK_PACKET_LEN;

  bool tcp_found = true;

  /* jump over the IP header(s) */
  switch (IPv4_version(((ipv4_hdr_t *)packet)->ver_hdrlen))
  {
    case IP_VERSION_4:
      /* do not support fragmented packets (but if fragmented, take the
         first fragment and assume, the SIP message is not damaged */
      if (! (IPv4_DF || (! (IPv4_FOF_MASK &
                ntohs(((ipv4_hdr_t *)packet)->flags_foff)) )) )
      {
#ifdef DEBUG
fprintf(stderr, "FRAGMENTED PACKET FOUND => exit processing\n");
#endif
        return;
      }

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

      cur_len -= IPv4_hdrlen(((ipv4_hdr_t *)packet)->ver_hdrlen);
#ifdef DEBUG
fprintf(stderr, "cur_len       %d\n"
                "ipv4 data len %d (MUST be the same as cur_len!)\n",
                cur_len,
                ntohs(((ipv4_hdr_t *)packet)->totallen)
                  - IPv4_hdrlen(((ipv4_hdr_t *)packet)->ver_hdrlen));
#endif
      packet +=  IPv4_hdrlen(((ipv4_hdr_t *)packet)->ver_hdrlen);
      CHECK_PACKET_LEN;

      break;

    case IP_VERSION_6:
      for (bool ipv6_hdr_found = true; ipv6_hdr_found; )
      {
        switch (((ipv6_hdr_t *)packet)->nexthdr)
        {
          case IPPROTO_TCP:
            tcp_found = true;
            ipv6_hdr_found = false;
            break;
          case IPPROTO_UDP:
            tcp_found = false;
            ipv6_hdr_found = false;
            break;
          case IPPROTO_IPV6:
            break;
          default:
            return;
        }

        cur_len -= sizeof(ipv6_hdr_t);
#ifdef DEBUG
fprintf(stderr, "cur_len       %d\n"
                "ipv6 data len %d (MUST be the same as cur_len!)\n",
                cur_len,
                ntohs(((ipv6_hdr_t *)packet)->payloadlen));
#endif
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
#ifdef DEBUG
fprintf(stderr, "sizeof(tcp_hdr_t) %ld\n"
                "TCP header len    %d (MUST be the same as sizeof(tcp_hdr_t)!)\n",
                sizeof(tcp_hdr_t),
                TCP_hdrlen(ntohs(((tcp_hdr_t *)packet)->len_res_con)));
#endif
    cur_len -= sizeof(tcp_hdr_t);
    packet  += sizeof(tcp_hdr_t);
  }
  /* jump over the UDP header */
  else
  {
    cur_len -= sizeof(udp_hdr_t);
#ifdef DEBUG
fprintf(stderr, "cur_len        %d\n"
                "UDP header len %ld (MUST be the same as cur_len!)\n",
                cur_len,
                ntohs(((udp_hdr_t *)packet)->len)
                  - sizeof(udp_hdr_t));
#endif
    packet  += sizeof(udp_hdr_t);
  }

  CHECK_PACKET_LEN;

  /* FIXME print source and destination IP addresses */
  //printf("src: %s\n", inet_ntoa(ip->ip_src));
  //printf("dst: %s\n", inet_ntoa(ip->ip_dst));

  // FIXME handle_sip_data(packet, header->caplen - (packet - _packet));
  handle_sip_data((payload_mem_t *)mem, packet, cur_len);
}

/** parse SIP data and print some of the extracted info */
void handle_sip_data(payload_mem_t *mem, const uint8_t *data, const uint32_t len)
{
  //FIXME rtc start ulozit take do listu, v pripade ukonceni spojeni
  //  vycist z listu a podle toho vyresit tento problem :)
  //struct timespec ts_start;
  //clock_gettime(CLOCK_MONOTONIC, &ts_start);
  //ntp to muze bohuzel zmenit, takze i tak potrebuji
  //  if (new <= old) printf("undetectable (approaching zero)\n")

#ifdef DEBUG
fprintf(stderr, "--------------SIP data of size %d:\n", len);
#endif

  uint32_t l = 0;
  uint32_t offset = 0;

  /* loop through joined mem->lines */
  while (l + offset < len)
  {
    /* join mem->lines beginning with space */
    while (l + offset < len)
    {
      for (; l + offset < len && data[offset + l] != '\r'; ++l)
        mem->line[l] = data[offset + l];

      /* no need to check boundaries (we have space from removed network headers) */
      mem->line[l] = '\0';
      /* +2 jump over CR and LF */
      offset += l +2;
      l = 0;

      /* check boundaries + handle SIP line joining */
      if (offset < len && data[offset] != ' ') break;
    }

#ifdef DEBUG
fprintf(stderr, "__JOINED LINE|%s\n", mem->line);
#endif

    // zadam o zahajeni hovoru
    INVITE sip:bob@biloxi.com SIP/2.0
    To: Bob <sip:bob@biloxi.com>
    From: Alice <sip:alice@atlanta.com>;tag=1928301774
    Call-ID: a84b4c76e66710
    CSeq: 314159 INVITE
    // dostanu odpoved ringing
    SIP/2.0 180 Ringing
    To: Bob <sip:bob@biloxi.com>;tag=a6c85cf
    From: Alice <sip:alice@atlanta.com>;tag=1928301774
    Call-ID: a84b4c76e66710
    CSeq: 314159 INVITE
    // dostanu info, ze bob to vzal
    SIP/2.0 200 OK
    To: Bob <sip:bob@biloxi.com>;tag=a6c85cf
    From: Alice <sip:alice@atlanta.com>;tag=1928301774
    Call-ID: a84b4c76e66710
    CSeq: 314159 INVITE
    // potvrdim bobovi (primo jemu posilam), ze jsem dostala od nej veskere info, cimz se zahaji samotny hovor
    ACK sip:bob@192.0.2.4 SIP/2.0
    To: Bob <sip:bob@biloxi.com>;tag=a6c85cf
    From: Alice <sip:alice@atlanta.com>;tag=1928301774
    Call-ID: a84b4c76e66710
    CSeq: 314159 ACK
    // bob ukoncuje hovor (primo mne posila info)
    BYE sip:alice@pc33.atlanta.com SIP/2.0
    From: Bob <sip:bob@biloxi.com>;tag=a6c85cf
    To: Alice <sip:alice@atlanta.com>;tag=1928301774
    Call-ID: a84b4c76e66710
    CSeq: 231 BYE
    // ja bobovi potvrdim to ukonceni
    SIP/2.0 200 OK
    From: Bob <sip:bob@biloxi.com>;tag=a6c85cf
    To: Alice <sip:alice@atlanta.com>;tag=1928301774
    Call-ID: a84b4c76e66710
    CSeq: 231 BYE

    //FIXME re-INVITE nesmi zpusobit zmenu sezeni (bude mit stejnou Call-ID ale muze prijit z obou smeru)
    //by default: INVITE:
    //              if exists(call_id): set state=invite caller= callee=
    //              else:               set state=invite caller= callee= call_id=Call-ID time_start=timestamp
    //            SIP/2.0 200 OK:
    //              if exists(call_id): set state=calling, vypsat ten cas zahajeni a kdo komu vola
    //            prijme BYE; vypise cas zahajeni a kdo komu vola a delku hovoru
    //-a: prida info o prozvoneni + odmitnuti
    //    prozvoneni == CANCEL [see section 10]
    //      if ! exists(call_id) -> return() // proste se ignoruje
    //      >>>If UAC wishes to give up on its call attempt entirely, it can send a CANCEL.
    //    odmitnuti == SIP/2.0 non-200 ???: stejne jako u "default BYE" + duvod neprijeti:
    //      486 (Busy Here)
    //      600 (Busy Everywhere)
    //      488 (Not Acceptable Here) - tady rozparsovat jeste "Warning header",
    //          ktery obsahuje detaily proc to bylo zamitnuto
    //        Warning: 370 devnull "Choose a bigger pipe"
    //        Warning: 370 devnull "CHOOSE A BIGGER PIPE"
    //        pokud neni pritomen, tak REASON==unknown
    //      pokud nejaky dalsi chybovy stav, tak REASON==unknown
    //-c: modifikuje "default" tak, ze pri "SIP/2.0 200 OK" nic nevypisuje
    //-f: pokud non-NULL, vypsat pouze hovody od <id>
    //-u: pokud non-NULL, vypsat pouze hovody pro <id>

    //if (regexec(&regex, "my string", SUBEXPR, mem->pmatch, 0))
    //{
    //  THROW_ERR_RET("bad URI format, look at RFC 3986", msg);
    //}

    //strncpy(protocol, loc + pmatch[EXPR_PROTO].rm_so,
    //    pmatch[EXPR_PROTO].rm_eo - pmatch[EXPR_PROTO].rm_so);
    //protocol[pmatch[EXPR_PROTO].rm_eo - pmatch[EXPR_PROTO].rm_so] = '\0';
  }

  fflush(stdout);
}

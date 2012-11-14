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
#include <time.h>
#include <assert.h>
#include "common.h"
#include "args.h"
#include "monitor.h"
#include "list_sip.h"

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

  if ((mem.line = malloc(sizeof(char) * RING_BUF_SIZE)) == NULL)
    MALLOC_EXIT;
  memset((void *)mem.pmatch, 0, MAX_ERE_LEN);
  if (regcomp(&mem.sip_invite,  ERE_SIP_INVITE,  REG_EXTENDED)) REGCOMP_EXIT;
  if (regcomp(&mem.sip_cancel,  ERE_SIP_CANCEL,  REG_EXTENDED)) REGCOMP_EXIT;
  if (regcomp(&mem.sip_bye,     ERE_SIP_BYE,     REG_EXTENDED)) REGCOMP_EXIT;
  if (regcomp(&mem.sip_status,  ERE_SIP_STATUS,  REG_EXTENDED)) REGCOMP_EXIT;
  if (regcomp(&mem.sip_from,    ERE_SIP_FROM,    REG_EXTENDED)) REGCOMP_EXIT;
  if (regcomp(&mem.sip_to,      ERE_SIP_TO,      REG_EXTENDED)) REGCOMP_EXIT;
  if (regcomp(&mem.sip_call_id, ERE_SIP_CALL_ID, REG_EXTENDED)) REGCOMP_EXIT;
  if (regcomp(&mem.sip_warning, ERE_SIP_WARNING, REG_EXTENDED)) REGCOMP_EXIT;
  mem.calls = list_sip_init();

#ifdef DEBUG
  printf("########  [%ld]  %s\n", MAX_ERE_LEN, ERE_SIP_INVITE );
  printf("########  [%ld]  %s\n", MAX_ERE_LEN, ERE_SIP_CANCEL );
  printf("########  [%ld]  %s\n", MAX_ERE_LEN, ERE_SIP_BYE    );
  printf("########  [%ld]  %s\n", MAX_ERE_LEN, ERE_SIP_STATUS );
  printf("########  [%ld]  %s\n", MAX_ERE_LEN, ERE_SIP_FROM   );
  printf("########  [%ld]  %s\n", MAX_ERE_LEN, ERE_SIP_TO     );
  printf("########  [%ld]  %s\n", MAX_ERE_LEN, ERE_SIP_CALL_ID);
  printf("########  [%ld]  %s\n", MAX_ERE_LEN, ERE_SIP_WARNING);
#endif

  int ret = pcap_loop(global_vars.handle, -1, handle_packet, (void *)&mem);

  pcap_close(global_vars.handle);
  free(mem.line);
  regfree(&mem.sip_invite );
  regfree(&mem.sip_cancel );
  regfree(&mem.sip_bye    );
  regfree(&mem.sip_status );
  regfree(&mem.sip_from   );
  regfree(&mem.sip_to     );
  regfree(&mem.sip_call_id);
  regfree(&mem.sip_warning);
  list_sip_dispose(mem.calls);

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
#ifdef DEBUG
  uint32_t cur_len = header->caplen; /* captured length */
#endif
  uint8_t *packet = (uint8_t *)_packet;

  /* jump over the ethernet header */
#ifdef DEBUG
  cur_len -= sizeof(eth_hdr_t);
#endif
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

#ifdef DEBUG
      cur_len -= IPv4_hdrlen(((ipv4_hdr_t *)packet)->ver_hdrlen);
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

#ifdef DEBUG
        cur_len -= sizeof(ipv6_hdr_t);
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
    cur_len -= sizeof(tcp_hdr_t);
#endif
    packet  += sizeof(tcp_hdr_t);
  }
  /* jump over the UDP header */
  else
  {
#ifdef DEBUG
    cur_len -= sizeof(udp_hdr_t);
    fprintf(stderr, "cur_len        %d\n"
        "UDP header len %ld (MUST be the same as cur_len!)\n",
        cur_len,
        ntohs(((udp_hdr_t *)packet)->len)
        - sizeof(udp_hdr_t));
#endif
    packet  += sizeof(udp_hdr_t);
  }

  CHECK_PACKET_LEN;

#ifdef DEBUG
  printf("!!!!!!!!!!!!!!!!!!  %d == %ld  !!!!!!!!!!!!!!!!!!!\n",
      cur_len, header->caplen - (packet - _packet));
  mem = mem;
#else
  handle_sip_data((payload_mem_t *)mem, packet, header->caplen - (packet - _packet));
#endif
}

#ifdef DEBUG
void print_regex_parts(char *str, regmatch_t *pmatch, int size)
{
  for (int i = 0; i < size; ++i)
  {
    if (pmatch[i].rm_so != -1)
    {
      char c = str[pmatch[i].rm_eo];
      str[pmatch[i].rm_eo] = '\0';
      char *_str = str + pmatch[i].rm_so;
      printf("%%%%%%%%%%%%%%  [%d] %s\n", i, _str);
      str[pmatch[i].rm_eo] = c;
    }
  }
}
#endif

#define MIDDLE_OUTPUT \
  if (sip_data->from_label[0] != '\0') \
    printf(" (%s)", sip_data->from_label); \
  printf("\n  callee: %s", sip_data->to); \
  if (sip_data->to_label[0] != '\0') \
    printf(" (%s)", sip_data->to_label);

#define save_string_from_regex(tmp, var, index) \
  do { \
        (tmp) = mem->pmatch[(index)].rm_eo - \
                mem->pmatch[(index)].rm_so; \
        if (((var) = malloc(sizeof(char) * ((tmp) +1))) == NULL) MALLOC_EXIT; \
        strncpy((var), mem->line + mem->pmatch[(index)].rm_so, (tmp)); \
        (var)[(tmp)] = '\0'; \
  } while (0)

/** parse SIP data and print some of the extracted info */
void handle_sip_data(payload_mem_t *mem, const uint8_t *data, const uint32_t len)
{
  //FIXME rtc start ulozit take do listu, v pripade ukonceni spojeni
  //  vycist z listu a podle toho vyresit tento problem :)
  //struct timespec ts_start {;
  //clock_gettime(CLOCK_MONOTONIC, &ts_start);
  //time_t   tv_sec; /* secs */
  //long     tv_nsec; /* nanoseconds */
  //ntp to muze bohuzel zmenit, takze i tak potrebuji
  //  if (new <= old) printf("undetectable (approaching zero)\n")

#ifdef DEBUGG
  fprintf(stderr, "--------------SIP data of size %d:\n", len);
#endif

  uint32_t l = 0;
  uint32_t offset = 0;

  sip_method_t method = SIP_METHOD_UNKNOWN;
  char status[] = "200";
  char *reason = NULL;
  char *from_label = NULL;
  char *from_addr = NULL;
  char *to_label = NULL;
  char *to_addr = NULL;
  char *call_id = NULL;
  char *warning = NULL;
  int tmp;
  list_sip_data_t *sip_data = NULL;
  struct tm my_tm;

#define STRFTIME_FORMAT "%d.%m.%Y %H:%M:%S"
  char strftime_res[] = "14.11.2012 19:58:29";

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

    //otestovat
    //  kompilaci pod FreeBSD ve virtualu
    //  obycejny start + stop ekiga
    //  zavolat na nesmysl bez zavinace
    //  zavolat na nesmysl se zavinacem
    //  zavolat na existujici linku, ktera to nevezme a budu to muset ukoncit
    //  zavolat na linku, ktera to vezme a ja to ukoncim
    //  zavolat na linku, ktera to vezme a ukonci
    //  zavolat na linku, ktera to odmitne

    if (method == SIP_METHOD_UNKNOWN)
    {
      /* we are interested only in the following methods */
      if      (! regexec(&mem->sip_invite, mem->line, MAX_ERE_LEN, mem->pmatch, 0))
      {
        method = SIP_METHOD_INVITE;
      }
      else if (! regexec(&mem->sip_cancel, mem->line, MAX_ERE_LEN, mem->pmatch, 0))
      {
        method = SIP_METHOD_CANCEL;
      }
      else if (! regexec(&mem->sip_bye,    mem->line, MAX_ERE_LEN, mem->pmatch, 0))
      {
        method = SIP_METHOD_BYE;
      }
      else if (! regexec(&mem->sip_status, mem->line, MAX_ERE_LEN, mem->pmatch, 0))
      {
        method = SIP_METHOD_STATUS;

        strncpy(status, mem->line + mem->pmatch[ERE_SIP_STATUS_STATUS_I].rm_so, 3);

        tmp = mem->pmatch[ERE_SIP_STATUS_REASON_I].rm_eo -
              mem->pmatch[ERE_SIP_STATUS_REASON_I].rm_so;
        if ((reason = malloc(sizeof(char) * (tmp +1))) == NULL) MALLOC_EXIT;
        strncpy(reason, mem->line + mem->pmatch[ERE_SIP_STATUS_REASON_I].rm_so, tmp);
        reason[tmp] = '\0';
      }
      else
      {
#ifdef DEBUGG
        fprintf(stderr, ">>> WTF METHOD => return\n");
#endif
        return;
      }
    }
    else
    {
      if (! regexec(&mem->sip_from, mem->line, MAX_ERE_LEN, mem->pmatch, 0))
      {
        save_string_from_regex(tmp, from_label, ERE_SIP_FROM_TO_LABEL_I);
        save_string_from_regex(tmp, from_addr,  ERE_SIP_FROM_TO_ADDR_I);
      }
      else if (! regexec(&mem->sip_to, mem->line, MAX_ERE_LEN, mem->pmatch, 0))
      {
        save_string_from_regex(tmp, to_label, ERE_SIP_FROM_TO_LABEL_I);
        save_string_from_regex(tmp, to_addr,  ERE_SIP_FROM_TO_ADDR_I);
      }
      else if (! regexec(&mem->sip_call_id, mem->line, MAX_ERE_LEN, mem->pmatch, 0))
      {
        save_string_from_regex(tmp, call_id, ERE_SIP_CALL_ID_I);
      }
      else if (! regexec(&mem->sip_warning, mem->line, MAX_ERE_LEN, mem->pmatch, 0))
      {
        save_string_from_regex(tmp, warning, ERE_SIP_WARNING_I);
      }
#ifdef DEBUGG
      else
      {
        fprintf(stderr, ">>> LINE does NOT match\n");
      }
#endif
    }

    /* avoid processing unnecessary data */
    if (call_id != NULL &&
        ((method == SIP_METHOD_INVITE && from_addr != NULL && to_addr != NULL) ||
         (method == SIP_METHOD_CANCEL) ||
         (method == SIP_METHOD_BYE) ||
         (method == SIP_METHOD_STATUS && warning != NULL))
       ) break;
  }

  if (method == SIP_METHOD_INVITE)
  {
#ifdef DEBUGG
    printf("--INVITE\n");
#endif
    if ((sip_data = list_sip_item_present(mem->calls, call_id)) == NULL)
    {
      if ((sip_data = malloc(sizeof(list_sip_data_t))) == NULL) MALLOC_EXIT;

      assert(clock_gettime(CLOCK_MONOTONIC, &sip_data->start_time) == 0);
      sip_data->last_state = method;
      sip_data->from       = from_addr;  from_addr  = NULL;
      sip_data->from_label = from_label; from_label = NULL;
      sip_data->to         = to_addr;    to_addr    = NULL;
      sip_data->to_label   = to_label;   to_label   = NULL;
      sip_data->call_id    = call_id;    call_id    = NULL;

      list_sip_add(mem->calls, sip_data);
    }
    /* handle re-INVITE -> update from & to*/
    else
    {
      sip_data->last_state = method;

      free(sip_data->from);
      sip_data->from = from_addr;
      from_addr = NULL;

      free(sip_data->from_label);
      sip_data->from_label = from_label;
      from_label = NULL;

      free(sip_data->to);
      sip_data->to = to_addr;
      to_addr = NULL;

      free(sip_data->to_label);
      sip_data->to_label = to_label;
      to_label = NULL;
    }
  }
  else if ((sip_data = list_sip_item_present(mem->calls, call_id)) != NULL)
  {
    switch (method)
    {
      case SIP_METHOD_CANCEL:
#ifdef DEBUGG
        printf("--CANCEL\n");
#endif
        printf("drop-call\n  caller: %s", sip_data->from);

        MIDDLE_OUTPUT

        fputs("\n", stdout);
        list_sip_remove(mem->calls, sip_data);
        break;

      case SIP_METHOD_BYE:
#ifdef DEBUGG
        printf("--BYE\n");
#endif
        struct timespec ts;
        assert(clock_gettime(CLOCK_MONOTONIC, &ts) == 0);
        time_t tt = MAX(ts.tv_sec - sip_data->start_time.tv_sec, 0);
        strftime(strftime_res, sizeof(strftime_res), STRFTIME_FORMAT,
            gmtime_r(&tt, &my_tm));

        printf("end call [%s]:\n  caller: %s", strftime_res, sip_data->from);

        MIDDLE_OUTPUT

        printf("\n  duration: %s\n", strftime_res);
        list_sip_remove(mem->calls, sip_data);
        break;

      /* SIP_METHOD_STATUS (SIP_METHOD_UNKNOWN is impossible) */
      default:
#ifdef DEBUGG
        printf("--STATUS\n");
#endif
        //FIXME pozor, tohle muze byt i odpoved brany, ze se nas
        //  nepodarilo spojit

        /* STATUS can not terminate session => we are not interested in it */
        if (sip_data->last_state != SIP_METHOD_INVITE) break;

        if (! strncmp(status, "200", 3))
        {
          sip_data->last_state = SIP_METHOD_STATUS;

          strftime(strftime_res, sizeof(strftime_res), STRFTIME_FORMAT,
              gmtime_r(&sip_data->start_time.tv_sec, &my_tm));

          printf("new call [%s]:\n  caller: %s", strftime_res, sip_data->from);

          MIDDLE_OUTPUT

          fputs("\n", stdout);
        }
        else
        {
          printf("deny call [%s", (reason == NULL) ? "Unknown reason" : reason);

          /* 486 600 ... => nothing; 488 => see Warning: */
          if (warning != NULL && ! strncmp(status, "488", 3))
            printf(" (%s)", warning);

          printf("]:\n  caller: %s", sip_data->from);

          MIDDLE_OUTPUT

          fputs("\n", stdout);
          list_sip_remove(mem->calls, sip_data);
#ifdef DEBUGGG
          if (! strncmp(status, "486", 3))
            printf("MUST BE|Busy Here\n");
          else if (! strncmp(status, "600", 3))
            printf("MUST BE|Busy Everywhere\n");
          else if (! strncmp(status, "488", 3))
            printf("MUST BE|Not Acceptable Here\n");
          else
            printf("MUST BE|????Unknown reason?????\n");
#endif
        }
    }
#ifdef DEBUGG
    printf("status     %sXXX\n", status    );
    printf("reason     %sXXX\n", reason    );
    printf("from_label %sXXX\n", from_label);
    printf("from_addr  %sXXX\n", from_addr );
    printf("to_label   %sXXX\n", to_label  );
    printf("to_addr    %sXXX\n", to_addr   );
    printf("call_id    %sXXX\n", call_id   );
#endif
  }

  if (reason     != NULL) free(reason);
  if (from_label != NULL) free(from_label);
  if (from_addr  != NULL) free(from_addr);
  if (to_label   != NULL) free(to_label);
  if (to_addr    != NULL) free(to_addr);
  if (call_id    != NULL) free(call_id);

  fflush(stdout);
#ifdef DEBUG
  fflush(stderr);
#endif
}

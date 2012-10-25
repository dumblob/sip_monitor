/*
 * Jan Pacner xpacne00@stud.fit.vutbr.cz
 * 2012-10-15 10:28:53 CEST
 */

#include "monitor.c"

{
  fprintf(stderr, "ERR: %s \"%s\"\n", errbuf, args->i);
  return EXIT_FAILURE;
}

// FIXME MALLOC_EXIT

// libpcap
// prepnout do promiskuit
// pcap_datalink() ziska info o eth_int
//   --pcap_lookupdev() pripojeni k sitovemu rozhrani
//   pcap_open_live() pcap_open_offline() otevreni rozhrani pro cteni
//   pcap_dispatch() pcap_loop() pcap_next() cteni paketu
//   sam musim analyzovat paket

int start_sip_monitoring(args_s *args);
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

  if (pcap_setfilter(handle, &filter))
  {
    fprintf(stderr, "ERR: %s \"%s\"\n", pcap_geterr(handle), args->i);
    return EXIT_FAILURE;
  }

  //FIXME man pcap-filter

  struct pcap_pkthdr *_header, header;
  u_char *_data, *data;

  if ((data = malloc(RING_BUF_SIZE)) == NULL) MALLOC_EXIT;

  //FIXME sigset(term int hup); handler() { do_stop = true; }
  unsigned char do_stop = 0;

  while (! do_stop)
  {
    /* -2 read from file; -1 fail; 0 timeout expired; 1 OK */
    if (pcap_next_ex(handle, &_header, &_data) == 1)
    {
      header.ts = _header->ts;
      header.caplen = _header->caplen;  /* stored size */
      header.len = _header->len;  /* real packet size (can be > than caplen) */
      memcpy(data, _data, header->len);
    }

    // net/ethernet.h ETHERTYPE_IPV6 ETHERTYPE_IP
    ((struct ether_header *)data)->ether_type;
  }

  pcap_close(handle);
  return EXIT_SUCCESS;
}

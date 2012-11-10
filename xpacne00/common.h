/*
 * Jan Pacner xpacne00@stud.fit.vutbr.cz
 * 2012-10-15 10:28:53 CEST
 */

#ifndef LOCAL_COMMON_H
#define LOCAL_COMMON_H

#include <stdint.h>  /* HACK for pcap missing u_int u_short etc. ( */
#define __USE_BSD    /*   needed under Linux)                      */
#include <pcap.h>

#include <stdio.h>
#include <stdlib.h>

#define MY_EXIT(x) do { \
  fputs(x "!\n", stderr); \
  exit(EXIT_FAILURE); \
} while (0)

#define REGCOMP_EXIT MY_EXIT("regcomp failed")
#define MALLOC_EXIT MY_EXIT("malloc failed")

struct global_vars_s {
  pcap_t *handle;
} global_vars;

typedef enum {
  SIP_METHOD_UNKNOWN,  /* not part of SIP RFC */
  SIP_METHOD_INVITE,
  SIP_METHOD_CANCEL,
  SIP_METHOD_BYE,
  SIP_METHOD_STATUS
} sip_method_t;

#endif

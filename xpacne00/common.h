/*
 * Jan Pacner xpacne00@stud.fit.vutbr.cz
 * 2012-10-15 10:28:53 CEST
 */

#ifndef LOCAL_COMMON_H
#define LOCAL_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

#define MALLOC_EXIT do { \
  fputs("malloc failed!\n", stderr); \
  fflush(stderr); \
  exit(EXIT_FAILURE); \
} while (0)

struct {
  pcap_t *handle;
} global_vars;

#endif

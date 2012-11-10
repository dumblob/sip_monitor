/*
 * Jan Pacner xpacne00@stud.fit.vutbr.cz
 * 2012-10-15 10:28:53 CEST
 */

#ifndef LOCAL_ARGS_H
#define LOCAL_ARGS_H

#include <stdbool.h>
#include "list_str.h"

//FIXME
//extern char *optarg;
//extern int optind;
//extern int opterr;
//int getopt(int, char **, const char *);

typedef struct {
  bool implicit;  // no behaviour args given
  char *i;        // interface
  bool a;         // add info about declined calls
  bool c;         // put info only about ended calls
  list_str_t *f;  // put only calls from <id>
  list_str_t *t;  // put only calls for <id>
//            u      put only calls from or for <id>
} args_s;

void handle_args(int, char **, args_s *);

#endif

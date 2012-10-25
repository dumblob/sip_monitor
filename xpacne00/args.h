/*
 * Jan Pacner xpacne00@stud.fit.vutbr.cz
 * 2012-10-15 10:28:53 CEST
 */

#ifndef ARGS_H
#define ARGS_H

//#include <unistd.h>
//#include <stdlib.h>
//#include <stdio.h>
#include <stdbool.h>
#include <assert.h>
#include "list.h"

// FIXME vytvorit 2 nafukovaci pole (from, for) s ukazateli na ID z argv[]

typedef struct {
  bool implicit;  // no behaviour args given
  char *i;        // interface
  bool a;         // add info about declined calls
  bool c;         // put info only about ended calls
  list_t *f;      // put only calls from <id>
  list_t *t;      // put only calls for <id>
//       u           put only calls from or for <id>
} args_s;

void handle_args(int, char **, args_s *);

#endif

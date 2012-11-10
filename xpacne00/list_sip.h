/*
 * Jan Pacner xpacne00@stud.fit.vutbr.cz
 * 2012-10-15 10:28:53 CEST
 */

#ifndef LOCAL_LIST_SIP_H
#define LOCAL_LIST_SIP_H

#include <stdbool.h>
#include "common.h"

/* sip data list; no data copy, but data free! */

typedef struct {
  void *start_time;
  sip_method_t last_state; //FIXME is it really needed to save this
  char *from;
  char *to;
  char *call_id;
} list_sip_data_t;

typedef struct list_sip_item_s {
  list_sip_data_t *data;
  struct list_sip_item_s *next;
} list_sip_item_t;

typedef struct {
  list_sip_item_t *head;
} list_sip_t;

list_sip_t      *list_sip_init        (void);
void             list_sip_add         (list_sip_t *, list_sip_data_t *);
void             list_sip_remove      (list_sip_t *, char *);
list_sip_item_t *list_sip_item_present(list_sip_t *, char *);
void             list_sip_dispose     (list_sip_t *);

#endif

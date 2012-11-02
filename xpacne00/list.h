/*
 * Jan Pacner xpacne00@stud.fit.vutbr.cz
 * 2012-10-15 10:28:53 CEST
 */

#ifndef LOCAL_LIST_H
#define LOCAL_LIST_H

#define LIST_MIN_SIZE 8

#include <stdbool.h>

typedef struct list_str_item_s {
  char *data;
  struct list_str_item_s *next;
} list_str_item_t;

typedef struct {
  list_str_item_t *head;
} list_str_t;

list_str_t      *list_str_init        (void);
void             list_str_add         (list_str_t *, char *);
void             list_str_remove      (list_str_t *, char *);
list_str_item_t *list_str_item_present(list_str_t *, char *);
void             list_str_dispose     (list_str_t *);

#endif

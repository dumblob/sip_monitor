/*
 * Jan Pacner xpacne00@stud.fit.vutbr.cz
 * 2012-10-15 10:28:53 CEST
 */

#ifndef LOCAL_LIST_H
#define LOCAL_LIST_H

#define LIST_MIN_SIZE 8

#include <stdbool.h>

typedef char list_item_t;

typedef struct {
  list_item_t **head;
  unsigned int first_empty_place;  /* index */
  unsigned int size;  /* index */
  unsigned int allocated;  /* count */
} list_t;

list_t *list_init        ();
void    list_add         (list_t *, list_item_t *);
void    list_remove      (list_t *, list_item_t *);
bool    list_item_present(list_t *, list_item_t *);
void    list_dispose     (list_t *);

#endif

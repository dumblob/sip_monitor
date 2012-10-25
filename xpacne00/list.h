/*
 * Jan Pacner xpacne00@stud.fit.vutbr.cz
 * 2012-10-15 10:28:53 CEST
 */

#ifndef LIST_H
#define LIST_H

#define LIST_MIN_SIZE 8

#include <stdlib.h>

//FIXME
//typedef struct _list_item {
//  char *id,
//  struct _list_item *next
//} list_item_t;

typedef char *list_item_t;

typedef struct {
  list_item_t *head;
  unsigned int size;
  unsigned int allocated;
} list_t;

list_t *list_init        ();
void    list_add         (list_t *, char *);
void    list_item_present(list_t *, char *);
void    list_dispose     (list_t *);

#endif

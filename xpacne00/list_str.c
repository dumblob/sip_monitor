/*
 * Jan Pacner xpacne00@stud.fit.vutbr.cz
 * 2012-10-15 10:28:53 CEST
 */

#include <stdlib.h>  /* malloc */
#include <string.h>
#include <assert.h>
#include "common.h"
#include "list_str.h"

list_str_t *list_str_init(void)
{
  list_str_t *tmp;

  if ((tmp = malloc(sizeof(list_str_t))) == NULL) MALLOC_EXIT;

  tmp->head = NULL;

  return tmp;
}

/* add to start; do not copy data */
void list_str_add(list_str_t *l, char *d)
{
  assert(l != NULL);

  list_str_item_t *tmp;

  if ((tmp = malloc(sizeof(list_str_item_t))) == NULL) MALLOC_EXIT;

  tmp->data = d;
  tmp->next = l->head;

  l->head = tmp;
}

list_str_item_t *list_str_item_present(list_str_t *l, char *d)
{
  assert(l != NULL);

  if (d == NULL) return NULL;

  list_str_item_t *tmp = l->head;

  while (tmp != NULL)
  {
    if (! strcmp(tmp->data, d)) return tmp;

    tmp = tmp->next;
  }

  return NULL;
}

void list_str_dispose(list_str_t *l)
{
  assert(l != NULL);

  while (l->head != NULL)
  {
    list_str_item_t *tmp = l->head->next;
    free(l->head);
    l->head = tmp;
  }

  free(l);
}

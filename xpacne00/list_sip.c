/*
 * Jan Pacner xpacne00@stud.fit.vutbr.cz
 * 2012-10-15 10:28:53 CEST
 */

#include <stdlib.h>  /* malloc */
#include <string.h>
#include <assert.h>
#ifdef DEBUGG
#include <stdio.h>
#endif
#include "common.h"
#include "list_sip.h"
#include "monitor.h"

list_sip_t *list_sip_init (void)
{
  list_sip_t *tmp;

  if ((tmp = malloc(sizeof(list_sip_t))) == NULL) MALLOC_EXIT;

  tmp->head = NULL;

  return tmp;
}

/* add to start; do not copy data */
void list_sip_add(list_sip_t *l, list_sip_data_t *d)
{
  assert(l != NULL);

#ifdef DEBUGG
  printf("list_sip_add %s\n", d->call_id);
#endif

  list_sip_item_t *tmp;

  if ((tmp = malloc(sizeof(list_sip_item_t))) == NULL) MALLOC_EXIT;

  tmp->data = d;
  tmp->next = l->head;

  l->head = tmp;
}

#define list_sip_free_pointers(x) \
  do { \
    if ((x)->data->from       != NULL) free((x)->data->from); \
    if ((x)->data->from_label != NULL) free((x)->data->from_label); \
    if ((x)->data->to         != NULL) free((x)->data->to); \
    if ((x)->data->to_label   != NULL) free((x)->data->to_label); \
    if ((x)->data->call_id    != NULL) free((x)->data->call_id); \
  } while (0)

void list_sip_remove(list_sip_t *l, list_sip_data_t *item)
{
  assert(l != NULL);

#ifdef DEBUGG
  printf("list_sip_remove %s\n", item->call_id);
#endif

  list_sip_item_t *tmp = l->head;
  list_sip_item_t *prev = NULL;

  while (tmp != NULL)
  {
    if (tmp->data == item)
    {
      if (prev == NULL)
        l->head = tmp->next;
      else
        prev->next = tmp->next;

      list_sip_free_pointers(tmp);

      free(tmp->data);
      free(tmp);
      return;
    }

    prev = tmp;
    tmp = tmp->next;
  }
}

list_sip_data_t *list_sip_item_present(list_sip_t *l, char *call_id)
{
  assert(l != NULL);

  if (call_id == NULL) return NULL;

  list_sip_item_t *tmp = l->head;

  while (tmp != NULL)
  {
    if (! strcmp(tmp->data->call_id, call_id)) return tmp->data;

    tmp = tmp->next;
  }

  return NULL;
}

void list_sip_dispose (list_sip_t *l)
{
  assert(l != NULL);

  while (l->head != NULL)
  {
    list_sip_item_t *tmp = l->head->next;

    list_sip_free_pointers(l->head);

    free(l->head->data);
    free(l->head);
    l->head = tmp;
  }

  free(l);
}

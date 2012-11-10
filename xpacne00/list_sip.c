/*
 * Jan Pacner xpacne00@stud.fit.vutbr.cz
 * 2012-10-15 10:28:53 CEST
 */

#include <stdlib.h>  /* malloc */
#include <string.h>
#include <assert.h>
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

  list_sip_item_t *tmp;

  if ((tmp = malloc(sizeof(list_sip_item_t))) == NULL) MALLOC_EXIT;

  tmp->data = d;
  tmp->next = l->head;

  l->head = tmp;
}

void list_sip_remove(list_sip_t *l, char *call_id)
{
  assert(l != NULL);

  list_sip_item_t *tmp = l->head;
  list_sip_item_t *prev = NULL;

  while (tmp != NULL)
  {
    if (! strcmp(tmp->data->call_id, call_id))
    {
      if (prev == NULL)
        l->head = tmp->next;
      else
        prev->next = tmp->next;

      //FIXME
      //free(l->head->data->start_time)
      if (tmp->data->from    != NULL) free(tmp->data->from);
      if (tmp->data->to      != NULL) free(tmp->data->to);
      if (tmp->data->call_id != NULL) free(tmp->data->call_id);

      free(tmp->data);
      free(tmp);
      return;
    }

    prev = tmp;
    tmp = tmp->next;
  }
}

list_sip_item_t *list_sip_item_present(list_sip_t *l, char *call_id)
{
  assert(l != NULL);

  list_sip_item_t *tmp = l->head;

  while (tmp != NULL)
  {
    if (! strcmp(tmp->data->call_id, call_id)) return tmp;

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

    //FIXME
    //free(l->head->data->start_time)
    if (l->head->data->from    != NULL) free(l->head->data->from);
    if (l->head->data->to      != NULL) free(l->head->data->to);
    if (l->head->data->call_id != NULL) free(l->head->data->call_id);

    free(l->head->data);
    free(l->head);
    l->head = tmp;
  }

  free(l);
}

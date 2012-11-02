/*
 * Jan Pacner xpacne00@stud.fit.vutbr.cz
 * 2012-10-15 10:28:53 CEST
 */

#include <stdlib.h>  /* malloc */
#include <string.h>
#include "common.h"
#include "list.h"

list_t *list_init(void)
{
  list_t *tmp;

  if ((tmp = malloc(sizeof(list_t))) == NULL)
    MALLOC_EXIT;

  if ((*tmp->head = malloc(LIST_MIN_SIZE * sizeof(list_item_t *))) == NULL)
    MALLOC_EXIT;

  tmp->first_empty_place = 0;
  tmp->size = 0;
  tmp->allocated = LIST_MIN_SIZE;

  return tmp;
}

void list_add(list_t *l, list_item_t *data)
{
  assert(l != NULL);

  l->head[first_empty_place] = data;
  l->first_empty_place++;

  if (l->first_empty_place)

  /* puff up */
  if (l->size == l->allocated)
  {
    l->allocated = l->size + (l->size >> 2);

    if ((*l->head = realloc(l->head,
            l->allocated * sizeof(list_item_t *))) == NULL)
      MALLOC_EXIT;
  }

  /* we know, we don't need to copy the data */
  l->head[l->size] = data;

  l->size++;
}

void list_remove(list_t *l, list_item_t *data)
{
  assert(l != NULL);

  if (l->first_empty_place != NULL)
    for (unsigned int i = 0; i <= l->size; ++i)
      if (! strcmp(l->head[i], data)) return true;

  if (l->first_empty_place)
  return;
}

//FIXME list_item_present zmenit na list_map_stop_at_true
bool list_map_stop_at_true(list_t *l,
    (bool)(*cmp)(const list_item_t *, const list_item_t *),
    list_item_t *data)
{
  assert(l != NULL);

  for (unsigned int i = 0; i <= l->size; ++i)
    if (l->head[i] != NULL && cmp(l->head[i], data)) return true;

  return false;
}

void list_dispose(list_t *l)
{
  assert(l != NULL);

  free(l->head);
  free(l);
}

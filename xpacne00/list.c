/*
 * Jan Pacner xpacne00@stud.fit.vutbr.cz
 * 2012-10-15 10:28:53 CEST
 */

#include "list.h"

list_t *list_init(void)
{
  list_t *tmp;

  if ((tmp = malloc(sizeof(list_t))) == NULL)
    MALLOC_EXIT;

  if ((tmp->head = malloc(LIST_MIN_SIZE * sizeof(list_item_t *))) == NULL)
    MALLOC_EXIT;

  tmp->size = 0;
  tmp->allocated = LIST_MIN_SIZE;
  tmp->head[tmp->size] = NULL;

  return tmp;
}

void list_add(list_t *l, char *data)
{
  /* puff up */
  if (l->size == l->allocated)
  {
    l->allocated = l->size + (l->size >> 2);

    if ((tmp->head = realloc(
            l->allocated * sizeof(list_item_t *))
        ) == NULL)
      MALLOC_EXIT;
  }

  /* we know, we don't need to copy the data */
  l->head[l->size] = data;

  l->size++;
}

bool list_item_present(list_t *l, char *data)
{
  if (l->head[0] != NULL)
    for (int i = 0; i <= l->size; ++i)
      if (! strcmp(l->head[i], data)) return true;

  return false;
}

void list_dispose(list_t *l)
{
  if (l != NULL)
  {
    free(l->head);
    free(l);
  }
}

/*
 * iot_list.c
 *
 *  Created on: 04 Feb 2019
 *      Author: hein
 */

#include <time.h>
#include <stdlib.h>

#include "utils.h"

typedef struct iot_list {
  char                      *id;
  char                      *data;
  time_t                    timestamp;
} iot_list_t;


static list_t *iot_list = NULL;

// todo - write to a file json xml yaml whateva

void iot_list_update (char *id, char *data)
{
  bool updated = true;

  list_t *list_walker = iot_list;

  while (list_walker)
  {
    iot_list_t *iot_list_item = list_walk (&list_walker);

//    if (strcmp (iot_list_item->id, id) == 0)
    if (strcasecmp (iot_list_item->id, id) == 0)
    {
      if (iot_list_item->data)
        free (iot_list_item->data);

      iot_list_item->data = strdup (data);

      updated = true;
    }
  }

  if (!updated)
  {
    iot_list_t *iot_list_item = list_add (&iot_list, sizeof(iot_list_t), "iot list");

    if (iot_list_item)
    {
      iot_list_item->id = strdup (id);
      iot_list_item->data = strdup (data);
      iot_list_item->timestamp = time (0);
    }
  }
}

/*
 * iot_list.c
 *
 *  Created on: 04 Feb 2019
 *      Author: hein
 */

#include <time.h>
#include <stdlib.h>

#include "json.h"
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
  bool updated = false;

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

    DEBUG_PRINTF("updated %s|%s|%ld", iot_list_item->id, iot_list_item->data, iot_list_item->timestamp);
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

    DEBUG_PRINTF("new     %s|%s|%ld", iot_list_item->id, iot_list_item->data, iot_list_item->timestamp);
  }
}


char *iot_list_json (void)
{
  list_t *list_walker = iot_list;

  json_t *rsp_array = json_array ();

  while (list_walker)
  {
    iot_list_t *iot_list_item = list_walk (&list_walker);

    json_t *json_arr_item = json_object ();

    if (iot_list_item->id)
      json_object_set_new (json_arr_item, "id", json_string (iot_list_item->id));

    if (iot_list_item->data)
      json_object_set_new (json_arr_item, "data", json_string (iot_list_item->data));

    json_object_set_new (json_arr_item, "timestamp", json_integer (iot_list_item->timestamp));

    json_array_append_new (rsp_array, json_arr_item);
  }

  return json_dumps (rsp_array, JSON_ENSURE_ASCII | JSON_PRESERVE_ORDER | JSON_COMPACT);
}
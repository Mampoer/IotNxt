/*
 * endpoint_iot_list.c
 *
 *  Created on: 06 Feb 2019
 *      Author: iotprototype
 */


#include "file_serve.h"
#include "config.h"
#include "json.h"



typedef struct iot_config_info {
  char                  *host;
  char                  *user;
  char                  *key;

  json_t                *json_object;
} iot_config_info_t;



static void load_iot_config_values (json_t *root, iot_config_info_t *iot_config_info)
{
  DEBUG_PRINTF("\t ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");

  load_json_string_value ( root, &iot_config_info->host     , "host"      , "\t Host"             );
  load_json_string_value ( root, &iot_config_info->user     , "user"      , "\t User"             );
  load_json_string_value ( root, &iot_config_info->key      , "key"       , "\t Key"              );

  DEBUG_PRINTF("\t ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
}



void iot_config ( http_conn_t     *http_conn
                , char            *payload
                , bool            debug     )
{
  if (payload && strlen (payload))
  {
    iot_config_info_t iot_config_info;

    memset (&iot_config_info, 0, sizeof(iot_config_info_t));

    json_error_t error;

    iot_config_info.json_object      = json_loads (payload, JSON_PRESERVE_ORDER, &error);

    if (iot_config_info.json_object == NULL)
    {
      char err[256] = "";
      DEBUG_PRINTF("ERROR: CAN NOT LOAD JSON DATA, on line %d: %s", error.line, error.text);
      DEBUG_PRINTF ("%s", payload);
      snprintf (err, sizeof(err), "<html><h1>400 - Invalid JSON: line %d - %s</h1></html>", error.line, error.text);

      http_reply (http_conn, HTTP_RES_400, NULL, err, strlen (err));
    }
    else
    {
      load_iot_config_values (iot_config_info.json_object, &iot_config_info);

      bool save_config = false;

      if (iot_config_info.host)
      {
        if (strcmp (iot_config_info.host, config.api_host) != 0)
        {
          if (config.api_host)
            free (config.api_host);

          config.api_host = strdup (iot_config_info.host);

          save_config = true;

          DEBUG_PRINTF("new config item host: %s", config.api_host);
        }
      }

      if (iot_config_info.user)
      {
        if (strcmp (iot_config_info.user, config.api_user) != 0)
        {
          if (config.api_user)
            free (config.api_user);

          config.api_user = strdup (iot_config_info.user);

          save_config = true;

          DEBUG_PRINTF("new config item user: %s", config.api_user);
        }
      }

      if (iot_config_info.key)
      {
        if (strcmp (iot_config_info.key, config.api_key) != 0)
        {
          if (config.api_key)
            free (config.api_key);

          config.api_key = strdup (iot_config_info.key);

          save_config = true;

          DEBUG_PRINTF("new config item key:  %s", config.api_key);
        }
      }

      list_t *http_header_list = NULL;

      add_http_header (&http_header_list, "Content-Type", MIME_APPLICATION_JSON);

      http_reply (http_conn, HTTP_RES_200, http_header_list, NULL, 0);

      list_clear (&http_header_list, NULL, __func__);

      if (save_config)
      {
        // todo save config as xml or something
      }

      if (iot_config_info.host)
        free (iot_config_info.host);

      if (iot_config_info.user)
        free (iot_config_info.user);

      if (iot_config_info.key)
        free (iot_config_info.key);

      if (iot_config_info.json_object)
        json_decref  (iot_config_info.json_object);
    }
  }
  else
  {
    DEBUG_PRINTF("ERROR: Empty query");

    reply_error ( http_conn
                , "Empty query"
                , __SHORT_FILE__
                , __LINE__);
  }
}

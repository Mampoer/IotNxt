/*
 * endpoint_iot_device.c
 *
 *  Created on: 23 Jun. 2018
 *      Author: heindekock
 */

#include <stdlib.h>

#include "web_notification.h"
#include "file_serve.h"
#include "json.h"


typedef struct iot_device_info {
  http_conn_t           *http_conn;

  char                  *id;
  char                  *data;

  char                  *original;

  json_t                *json_object;

  int                   debug;
} iot_device_info_t;


#define CACHE_TIME 60 * 10  // clean up in 10 minutes


static int allocated_items_of_mem = 0;


static void load_iot_device_values (json_t *root, iot_device_info_t *iot_device_info)
{
  DEBUG_PRINTF("\t ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");

  load_json_string_value ( root, &iot_device_info->id     , "id"     , "\t ID"              );
  load_json_object_value ( root, &iot_device_info->data   , "data"   , "\t Data"            );

  DEBUG_PRINTF("\t ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
}


static void iot_device_cleanup (void *userdata)
{
  if (userdata)
  {
    iot_device_info_t *iot_device_info = userdata;

    allocated_items_of_mem --;

    DEBUG_PRINTF("\t iot_device_cleanup (%d)\n", allocated_items_of_mem);

    if (iot_device_info->id)
      free (iot_device_info->id);

    if (iot_device_info->data)
      free (iot_device_info->data);

    if (iot_device_info->original)
      free (iot_device_info->original);

    if (iot_device_info->json_object)
      json_decref  (iot_device_info->json_object);

    Timer_Cleanup (userdata);

    //free (iot_device_info); moved to release conn (caller)
  }
}


//static void json_find_respond ( http_conn_t *http_conn
//                              , char        *rsp
//                              , bool        debug       )
//{
//  if (rsp && http_conn)
//  {
//    DEBUG_PRINTF("\t %s", rsp);
//
//    list_t *http_header_list = NULL;
//
////    add_http_header (&http_header_list, "Content-Type", MIME_APPLICATION_JSON);
//    add_http_header (&http_header_list, "Content-Type", MIME_TEXT_HTML); // guestlink can not handle json mime type
//
//    http_reply (http_conn, HTTP_RES_200, http_header_list, rsp, strlen (rsp));
//
//    list_clear (&http_header_list, NULL, __func__);
//  }
//  else
//    DEBUG_PRINTF("ERROR: no conn!");
//}
//
//
//static void RespondWithReasonResponseOnly ( http_conn_t *http_conn
//                                          , int ResponseCode, int ReasonCode
//                                          , bool debug                        )
//{
//  if (http_conn)
//  {
//    json_t *TransResponse = json_object ();
//
//    char *rsp = NULL;
//
//    if (TransResponse != NULL)
//    {
//      json_object_set_new (TransResponse, "responseCode", json_integer (ResponseCode));
//      json_object_set_new (TransResponse, "reasonCode", json_integer (ReasonCode));
//
//      rsp = json_dumps (TransResponse, JSON_ENSURE_ASCII | JSON_PRESERVE_ORDER | JSON_COMPACT);
//
//      json_decref (TransResponse);
//    }
//
//    json_find_respond ( http_conn
//                      , rsp
//                      , debug );
//
//    if (rsp)
//      free (rsp);
//  }
//  else
//    DEBUG_PRINTF("ERROR: no conn!");
//}



void prototype_notification_callback (void *userdata, http_rsp_t *http_rsp, char *response, int len )
{
  http_conn_t *http_conn = (http_conn_t *)find_io (userdata);

  if (http_conn)
  {
    if (http_conn->endpoint_cleanup == iot_device_cleanup)
    {
      if (http_conn->endpoint_handle)
      {
        iot_device_info_t *iot_device_info = http_conn->endpoint_handle;

        if (iot_device_info->http_conn == http_conn)
        {
          if (http_rsp && response && len) // good query result
          {
            DEBUG_PRINTF("prototype io response: %.*s", len, response);

            http_reply (http_conn, http_rsp->status, NULL, response, len);
          }
          else
          {
            DEBUG_PRINTF("prototype io notify failed");
          }
        }
      }
    }
  }
}


void iot_device ( http_conn_t     *http_conn
                , char            *payload
                , bool            debug)
{
  if (payload && strlen(payload))
  {
    iot_device_info_t *iot_device_info = calloc (1, sizeof(iot_device_info_t));

    if (iot_device_info)
    {
      allocated_items_of_mem++;

      Timer_Add (CACHE_TIME, SingleShot, iot_device_cleanup, iot_device_info); // alwais in front

      iot_device_info->debug            = debug;
      iot_device_info->http_conn        = http_conn;

      http_conn->endpoint_cleanup       = iot_device_cleanup;
      http_conn->endpoint_handle        = iot_device_info;

      json_error_t error;

      iot_device_info->json_object      = json_loads (payload, JSON_PRESERVE_ORDER, &error);

      if (iot_device_info->json_object == NULL)
      {
        DEBUG_PRINTF("ERROR: CAN NOT LOAD JSON DATA!");
        DEBUG_PRINTF("Error: on line %d: %s", error.line, error.text);

//        RespondWithReasonResponseOnly ( http_conn
//                                      , ResponseError, ReasonCodeFieldMissing
//                                      , debug                                 );
      }
      else
      {
        if (iot_device_info->debug)
        {
          char *pretty = json_dumps (iot_device_info->json_object, JSON_INDENT(1) | JSON_PRESERVE_ORDER);
          DEBUG_PRINTF("\t Array object :%s", pretty);
          free (pretty);
        }

        load_iot_device_values (iot_device_info->json_object, iot_device_info);

        if (!iot_device_info->id)
        {
          DEBUG_PRINTF("\t Can not find device ID");

//          RespondWithReasonResponseOnly ( http_conn
//                                        , ResponseError, ReasonCodeFieldMissing
//                                        , debug                                   );

        }
        else
        {
          // store id + data
          // do web hook notification to external server

          iot_device_info->data = strdup (payload);

          do_web_hook_notification (  "https://prototype.iotnxt.io/api/v3/data/post"
                                    , payload
                                    , "api"
                                    , "dgcszsu7qhb5f3p0prcf1ckqpwimeydi"
                                    , prototype_notification_callback
                                    , http_conn
                                  );

          return;
        }
      }
    }
    else
    {
      DEBUG_PRINTF("PANIC PANIC PANIC: Could not create a transaction info");

//      RespondWithReasonResponseOnly ( http_conn
//                                    , ResponseError, ReasonCodeGeneralError
//                                    , debug                                   );

    }
  }
  else
  {
    DEBUG_PRINTF("ERROR: Empty query");

//    RespondWithReasonResponseOnly ( http_conn
//                                  , ResponseError, ReasonCodeFieldMissing
//                                  , debug                                   );
  }
}

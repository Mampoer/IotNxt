/*
 * endpoint_iot_list.c
 *
 *  Created on: 06 Feb 2019
 *      Author: iotprototype
 */


#include "file_serve.h"



char *iot_list_json (void);



void iot_list ( http_conn_t     *http_conn
              , char            *payload
              , bool            debug     )
{
  char *ret = iot_list_json ();

  DEBUG_PRINTF("\t (%s:%d) %s", http_conn->IO_Handle.ip, http_conn->IO_Handle.fd, ret);

  list_t *http_header_list = NULL;

  add_http_header (&http_header_list, "Content-Type", MIME_APPLICATION_JSON);

  http_reply (http_conn, HTTP_RES_200, http_header_list, ret, strlen(ret));

  list_clear (&http_header_list, NULL, __func__);

  free (ret);
}

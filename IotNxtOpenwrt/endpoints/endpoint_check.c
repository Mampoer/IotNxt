/*
 * endpoint_check.c
 *
 *  Created on: 15 Jun. 2018
 *      Author: heindekock
 */
#include <string.h>

#include "endpoints.h"
#include "file_serve.h"
#include "utils.h"


typedef void (*end_point_handler_t)   ( http_conn_t     *http_conn
                                      , char            *payload
                                      , bool            debug         );


typedef struct endpoint_def {
    const char                                *path;
    end_point_handler_t                       end_point_handler;
} endpoint_def_t;


const endpoint_def_t endpoint_def_array[] = {
    {"/api/v3/data/post"                , iot_device          },
    {"/api/v3/list"                     , iot_list            },
    {NULL                               , NULL                }
};


//void spr_find (https_conn_t *https_conn, char *query);
//void hpp_serve (https_conn_t *https_conn, char *query);


void endpoint_check   ( http_conn_t     *http_conn
                      , char            *path
                      , char            *payload      )
{
  const endpoint_def_t *endpoint_def = endpoint_def_array;

  //DEBUG_PRINTF ("(%s:%d) %s: %s", http_conn->IO_Handle.ip, http_conn->IO_Handle.fd, path, payload);

  while (endpoint_def->path && endpoint_def->end_point_handler)
  {
    if (strcmp (endpoint_def->path, path) == 0)
    {
      endpoint_def->end_point_handler ( http_conn
                                      , payload
                                      , false);

      return;
    }
    else
    if (strncmp ("/debug", path, 6) == 0)
    {
      if (strcmp (endpoint_def->path, &path[6]) == 0)
      {
        endpoint_def->end_point_handler ( http_conn
                                        , payload
                                        , true);

        return;
      }
    }

    endpoint_def++;
  }

  serve_file  ( http_conn
              , path );
}




/*
 * endpoint_iot_device.c
 *
 *  Created on: 23 Jun. 2018
 *      Author: heindekock
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdlib.h>

#include "file_serve.h"
#include "config.h"
#include "resolv.h"
#include "json.h"


#define USER_AGENT "IOTNXT"

#define CONN_IDLE_TIME ONE_MINUTE * 3

typedef struct iot_device_info {
  http_conn_t           *http_conn; // dont move from first pos so IO_Handle will be at same addr

  char                  *id;
  char                  *data;

  char                  *original;

  json_t                *json_object;

  char                  *url;
  char                  *server;
  char                  *ip;

  int                   port;

  char                  *request;

  http_rsp_t            http_rsp;
} iot_device_info_t;

typedef struct iot_server_info {
  IO_Handle_t           *IO_Handle;

  iot_device_info_t     *iot_device_handle;

  char                  *url;
  char                  *server;
  char                  *ip;

  int                   port;
} iot_server_info_t;


list_t *iot_server_list = NULL;

static int allocated_items_of_mem = 0;

void iot_list_update (char *id, char *data);
static void iot_server_resolv_callback (void *userdata, char *addr, char *ip);

static void load_iot_device_values (json_t *root, iot_device_info_t *iot_device_info)
{
  //DEBUG_PRINTF("\t ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");

  load_json_string_value ( root, &iot_device_info->id     , "id"     , "\t ID"              );
  load_json_object_value ( root, &iot_device_info->data   , "data"   , "\t Data"            );

  //DEBUG_PRINTF("\t ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
}


static char *http_post (char *Server, char *Path, char *User, char *Pass, char *request)
{
  char *buffer;
  char *auth = NULL;

  if (User && Pass)
    auth = basic_auth (User, Pass);

  if (request)
    asprintf (&buffer,  "POST /%s HTTP/1.1\r\n"
                        "Host: %s\r\n"
                        "User-Agent: %s\r\n"
                        "%s"
                        "%s"
                        "%s"
//                        "Connection: close\r\n"
                        "Content-Type: application/x-www-form-urlencoded\r\n"
                        "Content-Length: %zd\r\n\r\n%s"
              , Path
              , Server
              , USER_AGENT
              , auth ? "Authorization: Basic " : ""
              , auth ? auth : ""
              , auth ? "\r\n" : ""
              , strlen (request)
              , request);
  else
    asprintf (&buffer, "POST /%s HTTP/1.1\r\n"
                        "Host: %s\r\n"
                        "User-Agent: %s\r\n"
//                        "Connection: close\r\n"
                        "Accept: */*\r\n\r\n", Path, Server, USER_AGENT);

  if (auth)
  {
    free (auth);
  }

  return (buffer);
}


static void server_cleanup (void *userdata)
{
  if (userdata)
  {
    iot_server_info_t *iot_server_info = userdata;

    if (iot_server_info->iot_device_handle) // conn still busy - sever conn must have died
    {
      iot_device_info_t *iot_device_info = iot_server_info->iot_device_handle;

      DEBUG_PRINTF("(%s:%d) Active server conn error", iot_server_info->IO_Handle->ip, iot_server_info->IO_Handle->fd)

      char Path[1024] = "";
      char Server[255] = "";
      iot_device_info->port = 443;
//      iot_device_info->url = strdup ("https://prototype.iotnxt.io/api/v3/data/post");
      iot_device_info->url = strdup (config.api_host);

      if (ExplodeURL (iot_device_info->url, Server, &iot_device_info->port, Path) == 1)
      {
        iot_device_info->server   = strdup (Server);
//        iot_device_info->request  = http_post (Server, Path, "api", "dgcszsu7qhb5f3p0prcf1ckqpwimeydi", iot_device_info->original);
        iot_device_info->request  = http_post (Server, Path, config.api_user, config.api_pass, iot_device_info->original);

        if (iot_device_info->request)
        {
          resolv (iot_device_info->server, iot_server_resolv_callback, iot_device_info->http_conn);
        }
      }
    }

    if (iot_server_info->url)
      free (iot_server_info->url);

    if (iot_server_info->server)
      free (iot_server_info->server);

    if (iot_server_info->ip)
      free (iot_server_info->ip);
  }
}

static void server_io_cleanup (IO_Handle_t *IO_Handle) // server con died or sever kick us off
{
  if (IO_Handle)
  {
    list_t *list_walker = iot_server_list;

    while (list_walker)
    {
      iot_server_info_t *iot_server_info = list_walk (&list_walker);

      if (iot_server_info->IO_Handle == IO_Handle)
      {
        list_remove (&iot_server_list, iot_server_info, server_cleanup, NULL);

        DEBUG_PRINTF ("(%s:%d)\t server_io_cleanup (%d)", IO_Handle->ip, IO_Handle->fd, list_count (iot_server_list));
      }
    }
  }
}

static void iot_device_cleanup (void *userdata) // device side closed or killed
{
  if (userdata)
  {
    iot_device_info_t *iot_device_info = userdata;

    if (iot_device_info->id)
      free (iot_device_info->id);

    iot_device_info->id = NULL;

    if (iot_device_info->data)
      free (iot_device_info->data);

    iot_device_info->data = NULL;

    if (iot_device_info->original)
      free (iot_device_info->original);

    iot_device_info->original = NULL;

    if (iot_device_info->json_object)
      json_decref  (iot_device_info->json_object);

    iot_device_info->json_object = NULL;

    if (iot_device_info->url)
      free (iot_device_info->url);

    iot_device_info->url = NULL;

    if (iot_device_info->server)
      free (iot_device_info->server);

    iot_device_info->server = NULL;

    if (iot_device_info->ip)
      free (iot_device_info->ip);

    iot_device_info->ip = NULL;

    if (iot_device_info->request)
      free (iot_device_info->request);

    iot_device_info->request = NULL;

    Timer_Cleanup (iot_device_info);

    //free (iot_device_info); moved to release conn (caller)

    allocated_items_of_mem--;

//    DEBUG_PRINTF("(%s:%d)\t iot_device_cleanup (%d)"
//        , iot_device_info->http_conn->IO_Handle.ip
//        , iot_device_info->http_conn->IO_Handle.fd
//        , allocated_items_of_mem);
  }
}


static int server_io (IO_Handle_t *IO_Handle)
{
  int ret = 0;

  if (IO_Handle)
  {
    list_t *list_walker = iot_server_list;

    while (list_walker)
    {
      iot_server_info_t *iot_server_info = list_walk (&list_walker);

      if (iot_server_info->IO_Handle == IO_Handle)
      {
        if (iot_server_info->iot_device_handle)
        {
          iot_device_info_t *iot_device_info = iot_server_info->iot_device_handle;

          if (iot_device_info->http_conn)
          {
            if (iot_device_info->http_conn->endpoint_cleanup == iot_device_cleanup)
            {
              if (IO_Handle->tx_index == 0)
              {
                //DEBUG_PRINTF("(%s:%d) Send ready", IO_Handle->ip, IO_Handle->fd)

                if (iot_device_info->request)
                {
                  //DEBUG_PRINTF("(%s:%d) Sending:\n%s", iot_server_info->IO_out_Handle.ip, iot_server_info->IO_out_Handle.fd, iot_device_info->request);
                  io_buffer_out (IO_Handle, (uint8_t *) iot_device_info->request, strlen (iot_device_info->request));
                  free (iot_device_info->request);
                  iot_device_info->request = NULL;
                }
              }

              if (IO_Handle->rx_index)
              {
                if ((ret = http_parse_response ( &iot_device_info->http_rsp
                                               , (char *)IO_Handle->rx_buf
                                               , &IO_Handle->rx_index)))
                {
                  if (iot_device_info->http_rsp.content_length)
                  {
                    DEBUG_PRINTF("(%s:%d) IoT server response: %s: (%d) %.*s"
                        , IO_Handle->ip, IO_Handle->fd
                        , iot_device_info->url, iot_device_info->http_rsp.status
                        , iot_device_info->http_rsp.content_length
                        , IO_Handle->rx_buf + iot_device_info->http_rsp.headder_length);

                    http_reply  ( iot_device_info->http_conn
                                , iot_device_info->http_rsp.status
                                , NULL
                                , (char *)IO_Handle->rx_buf + iot_device_info->http_rsp.headder_length
                                , iot_device_info->http_rsp.content_length);
                  }

//                  DEBUG_PRINTF("(%s:%d) IoT server connection released", IO_Handle->ip, IO_Handle->fd);

                  iot_server_info->iot_device_handle = NULL;
                }
              }
            }
          }
        }
      }
    }
  }

  return ret;
}


static void iot_server_resolv_callback (void *userdata, char *addr, char *ip)
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
          if (ip && addr)
          {
            DEBUG_PRINTF("resolved %s as %s", addr, ip);

            iot_server_info_t *iot_server_info = list_add (&iot_server_list, sizeof(iot_server_info_t), "iot server");

            if (iot_server_info)
            {
              iot_server_info->IO_Handle = io_connect (ip, iot_device_info->port, 1, CONN_IDLE_TIME, 0);

              if (iot_server_info->IO_Handle )
              {
                iot_device_info->ip                     = strdup (ip);

                iot_server_info->IO_Handle->io_cleanup  = server_io_cleanup;
                iot_server_info->IO_Handle->io          = server_io;
                iot_server_info->iot_device_handle      = iot_device_info;

                iot_server_info->url                    = strdup (iot_device_info->url);
                iot_server_info->server                 = strdup (iot_device_info->server);
                iot_server_info->port                   = iot_device_info->port;
                iot_server_info->ip                     = strdup (ip);

                DEBUG_PRINTF ("(%s:%d) new connection", iot_device_info->ip, iot_server_info->IO_Handle->fd);

                return;
              }
              else
              {
                DEBUG_PRINTF("ERROR: No io handle created!");

                reply_error ( http_conn
                            , "No server io handle"
                            , __SHORT_FILE__
                            , __LINE__);
              }
            }
          }
          else
          {
            DEBUG_PRINTF("PANIC PANIC PANIC: Could not resolve %s", addr);

            reply_error ( http_conn
                        , "resolve error"
                        , __SHORT_FILE__
                        , __LINE__);
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
  if (payload && strlen (payload))
  {
    iot_device_info_t *iot_device_info = calloc (1, sizeof (iot_device_info_t));

    if (iot_device_info)
    {
      allocated_items_of_mem++;

//      Timer_Add (30 * ONE_MINUTE, SingleShot, device_cleanup_check, iot_device_info);

      iot_device_info->http_conn        = http_conn;

      http_conn->endpoint_cleanup       = iot_device_cleanup;
      http_conn->endpoint_handle        = iot_device_info;

      json_error_t error;

      iot_device_info->json_object      = json_loads (payload, JSON_PRESERVE_ORDER, &error);

      if (iot_device_info->json_object == NULL)
      {
        char err[256] = "";
        DEBUG_PRINTF("ERROR: CAN NOT LOAD JSON DATA, on line %d: %s", error.line, error.text);
        DEBUG_PRINTF ("%s", payload);
        snprintf (err, sizeof(err), "<html><h1>400 - Invalid JSON: line %d - %s</h1></html>", error.line, error.text);

        http_reply (http_conn, HTTP_RES_400, NULL, err, strlen (err));
      }
      else
      {
        load_iot_device_values (iot_device_info->json_object, iot_device_info);

        if (!iot_device_info->id)
        {
          DEBUG_PRINTF("\t Can not find device ID");

          reply_error ( http_conn
                      , "no device id"
                      , __SHORT_FILE__
                      , __LINE__);
        }
        else
        {
          iot_list_update (iot_device_info->id, iot_device_info->data);

          iot_device_info->original = strdup (payload);

          char Path[1024] = "";
          char Server[255] = "";
          iot_device_info->port = 443;
//          iot_device_info->url = strdup ("https://prototype.iotnxt.io/api/v3/data/post");
          iot_device_info->url = strdup (config.api_host);

          if (ExplodeURL (iot_device_info->url, Server, &iot_device_info->port, Path) == 1)
          {
            iot_device_info->server   = strdup (Server);
//            iot_device_info->request  = http_post (Server, Path, "api", "dgcszsu7qhb5f3p0prcf1ckqpwimeydi", payload);
            iot_device_info->request  = http_post (Server, Path, config.api_user, config.api_pass, payload);

            if (iot_device_info->request) // look for open server conn
            {
              list_t *list_walker = iot_server_list;

              while (list_walker)
              {
                iot_server_info_t *iot_server_info = list_walk (&list_walker);

                if (iot_server_info->iot_device_handle == NULL) // open
                {
                  if (strcmp (iot_server_info->server, Server) == 0) // same server
                  {
                    if (iot_server_info->port == iot_device_info->port) // same port - reuse
                    {
                      if (iot_server_info->IO_Handle->fd > 0)
                      {
                        if (iot_server_info->IO_Handle->io_cleanup == server_io_cleanup) // seems reusable
                        {
                          DEBUG_PRINTF("(%s:%d) reusing server connection"
                              , iot_server_info->IO_Handle->ip
                              , iot_server_info->IO_Handle->fd);

                          iot_server_info->iot_device_handle = iot_device_info; // reserve server conn

                          io_buffer_out ( iot_server_info->IO_Handle
                                        , (uint8_t *) iot_device_info->request
                                        , strlen (iot_device_info->request));

                          free (iot_device_info->request);
                          iot_device_info->request = NULL;

                          return;
                        }
                      }
                    }
                  }
                }
              }

              resolv (iot_device_info->server, iot_server_resolv_callback, http_conn);

              return;
            }
            else
            {
              DEBUG_PRINTF("PANIC PANIC PANIC: Could not build iot server request");

              reply_error ( http_conn
                          , "Can not build server request"
                          , __SHORT_FILE__
                          , __LINE__);
            }
          }
          else
          {
            DEBUG_PRINTF("PANIC PANIC PANIC: Could not find server from %s", iot_device_info->url);

            reply_error ( http_conn
                        , "Can not find server details"
                        , __SHORT_FILE__
                        , __LINE__);
          }
        }
      }
    }
    else
    {
      DEBUG_PRINTF("PANIC PANIC PANIC: Could not create iot device info");

      reply_error ( http_conn
                  , "Out of memory"
                  , __SHORT_FILE__
                  , __LINE__);
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

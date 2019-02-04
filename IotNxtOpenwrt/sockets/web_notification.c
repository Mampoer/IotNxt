/*
 * notification.c
 *
 *  Created on: 25 Oct 2017
 *      Author: root
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "utils.h"
#include "timer.h"
#include "resolv.h"
#include "picohttpparser.h"
#include "web_notification.h"

#define USER_AGENT "IOTNXT"

#define CONN_IDLE_TIME    60 * 3

typedef struct notification {
  IO_Handle_t               *IO_Handle;

  char                      *ip;
  int                       port;
  char                      *url;

  bool                      use_ssl;

  char                      *request;

  notification_callback_t   callback;
  void                      *userdata;

  http_rsp_t                http_rsp;

} notification_t;


static list_t *notification_list = NULL;


static int allocated_items_of_mem = 0;

char *alert_host = NULL;
int alert_port = 443;

static void notification_cleanup (void *userdata)
{
  if ( userdata )
  {
    notification_t *notification_list_item = userdata;;

    allocated_items_of_mem--;

    DEBUG_PRINTF ("notification_list_cleanup %d", allocated_items_of_mem);

    if (notification_list_item->callback)
      notification_list_item->callback (notification_list_item->userdata, NULL, NULL, 0);

    if (notification_list_item->url)              free (notification_list_item->url);
    if (notification_list_item->ip)               free (notification_list_item->ip);
    if (notification_list_item->request)          free (notification_list_item->request);

    Timer_Cleanup (userdata);
  }
}


static void notification_io_cleanup (IO_Handle_t *IO_Handle)
{
  list_t *list_walker = notification_list;

  while (list_walker)
  {
    notification_t *notification = list_walk (&list_walker);

    if (notification->IO_Handle == IO_Handle)
    {
      list_remove (&notification_list, notification, notification_cleanup, __func__);
    }
  }
}


static int notification_parse (notification_t *notification)
{
  if (notification)
  {
    if (notification->IO_Handle)
    {
      if (http_parse_response (&notification->http_rsp, (char *)notification->IO_Handle->rx_buf, &notification->IO_Handle->rx_index))
      {
        if (notification->http_rsp.content_length)
        {
          DEBUG_PRINTF("Web notification response: %s: (%d) %.*s", notification->url, notification->http_rsp.status, notification->http_rsp.content_length, notification->IO_Handle->rx_buf + notification->http_rsp.headder_length);
        }

        if (notification->callback)
          notification->callback (notification->userdata, &notification->http_rsp, (char *)notification->IO_Handle->rx_buf + notification->http_rsp.headder_length, notification->http_rsp.content_length);

        notification->callback = NULL;

        release_io (notification->IO_Handle);
      }
    }
  }

  return 0;
}


static int notification_io (IO_Handle_t *IO_Handle)
{
  if (IO_Handle)
  {
    list_t *list_walker = notification_list;

    while (list_walker)
    {
      notification_t *notification = list_walk (&list_walker);

      if (notification->IO_Handle == IO_Handle)
      {
        if (notification->IO_Handle->tx_index == 0)
        {
          DEBUG_PRINTF("(%s:%d) Send ready", notification->IO_Handle->ip, notification->IO_Handle->fd)

          if (notification->request)
          {
            DEBUG_PRINTF("(%s:%d) Sending:\n%s", notification->IO_Handle->ip, notification->IO_Handle->fd, notification->request);
            io_buffer_out (notification->IO_Handle, (uint8_t *) notification->request, strlen (notification->request));
            free (notification->request);
            notification->request = NULL;
          }
        }

        if (notification->IO_Handle->rx_index)
          return notification_parse (notification);
      }
    }
  }

  return 0;
}


static void notification_resolv_callback (void *userdata, char *addr, char *ip)
{
  notification_t *notification = list_find (notification_list, userdata);

  DEBUG_PRINTF("resolved %s as %s", addr, ip);

  if (notification)
  {
    if (ip && addr)
    {
      notification->IO_Handle = io_connect (ip, notification->port, 1, CONN_IDLE_TIME, sizeof(IO_Handle_t));

      if (notification->IO_Handle)
      {
        notification->IO_Handle->io_cleanup = notification_io_cleanup;
        notification->IO_Handle->io         = notification_io;

        notification->ip                    = strdup (ip);

        DEBUG_PRINTF ("(%s:%d) new connection", notification->ip, notification->IO_Handle->fd);

        return;
      }
      else
      {
        DEBUG_PRINTF("ERROR: No io handle created!");
      }
    }

    list_remove (&notification_list, notification, notification_cleanup, __func__);
  }
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


void do_web_hook_notification ( char                    *url
                              , char                    *data
                              , char                    *user
                              , char                    *key
                              , notification_callback_t callback
                              , void                    *userdata )
{
  notification_t *notification = list_add (&notification_list, sizeof(notification_t), "notification");

  if (notification)
  {
    allocated_items_of_mem++;

    notification->callback = callback;
    notification->userdata = userdata;

    char Path[1024] = "";
    char Server[255] = "";
    notification->port = 443;

    if (ExplodeURL (url, Server, &notification->port, Path) == 1)
    {
      notification->url     = strdup (Server);
      notification->request = http_post (notification->url, Path, user, key, data);

      if (notification->request)
      {
        char *p = strstr (notification->request,"\r\n\r\n");

        if (p)
        {
          DEBUG_PRINTF("Web notification request: %s: %s", url, p + 4);
        }
        else
        {
          DEBUG_PRINTF("Web notification request: %s: %s", url, notification->request);
        }

        resolv (notification->url, notification_resolv_callback, notification);
      }
      else
        list_remove (&notification_list, notification, notification_cleanup, __func__);
    }
  }
  else
  {
    DEBUG_PRINTF("OUT OF MEMORY!");

    if (callback)
      callback (userdata, NULL, NULL, 0);
  }
}

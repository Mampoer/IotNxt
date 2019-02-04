/*
 * resolv.c
 *
 *  Created on: 28 Mei 2018
 *      Author: heindekock
 */


#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdlib.h>

#include <netdb.h>
//#include <errno.h>
//#include <fcntl.h>
//#include <unistd.h>
//#include <sys/socket.h>
//#include <arpa/inet.h>

#include "resolv.h"
#include "utils.h"
#include "timer.h"

typedef struct resolv
{
  char *ar_name;
  struct gaicb *req;
  resolv_callback_t callback;
  void *userdata;
} resolv_t;

static list_t *resolv_list = NULL;

static int allocated_items_of_mem = 0;

static void resolv_cleanup (void *userdata)
{
  if (userdata)
  {
    resolv_t *resolv_list_item = userdata;

    allocated_items_of_mem--;

    DEBUG_PRINTF ("resolv_list_cleanup %d", allocated_items_of_mem);

    if (resolv_list_item->callback)
      resolv_list_item->callback (resolv_list_item->userdata, resolv_list_item->ar_name, NULL);

    if (resolv_list_item->ar_name)
      free (resolv_list_item->ar_name);

    if (resolv_list_item->req)
      free (resolv_list_item->req);

    Timer_Cleanup (userdata);
  }
}

static void resolv_poll (void *userdata)
{
  resolv_t *resolv = list_find (resolv_list, userdata);

  if (resolv)
  {
    int ret = gai_error (resolv->req);

    if (!ret)
    {
      char host[NI_MAXHOST];

      ret = getnameinfo (resolv->req->ar_result->ai_addr
          , resolv->req->ar_result->ai_addrlen
          , host
          , sizeof(host)
          , NULL
          , 0
          , NI_NUMERICHOST);

      if (ret)
      {
        DEBUG_PRINTF ("resolv_poll getnameinfo for %s failed %s", resolv->ar_name, gai_strerror (ret));
        list_remove (&resolv_list, resolv, resolv_cleanup, __func__);
      }
      else
      {
        //DEBUG_PRINTF ("resolv_poll getnameinfo resolved %s as %s", reqs[resolv->dns_idx]->ar_name, host);

        if (resolv->callback)
          resolv->callback (resolv->userdata, resolv->ar_name, host);

        resolv->callback = NULL;
      }
    }
    else if (ret == EAI_INPROGRESS)
    {
      //DEBUG_PRINTF("Still busy resolving %s (%s:%3d| %5d) (%s)", reqs [ resolv->dns_idx]->ar_name, resolv->url, resolv->port, resolv->transaction->TransactionID );
      Timer_Add (1, SingleShot, resolv_poll, resolv);
      return;
    }
    else
    {
      DEBUG_PRINTF ("resolv gai error for %s failed %s", resolv->ar_name, gai_strerror (ret));
    }

    list_remove (&resolv_list, resolv, resolv_cleanup, __func__);
  }
}

void resolv (const char *url, resolv_callback_t callback, void *userdata)
{
  int ret;

  if (isValidIpAddress (url))
  {
    DEBUG_PRINTF("%s is an IP", url);

    if (callback)
      callback (userdata, (char *) url, (char *) url);

    return;
  }

  resolv_t *resolv = list_add (&resolv_list, sizeof(resolv_t), "dns");

  if (resolv)
  {
    allocated_items_of_mem++;

    resolv->callback = callback;
    resolv->userdata = userdata;
    resolv->ar_name  = strdup (url);

    resolv->req = calloc (1, sizeof(struct gaicb));

    if (!resolv->req)
    {
      list_remove (&resolv_list, resolv, resolv_cleanup, __func__);
      return;
    }

    resolv->req->ar_name = resolv->ar_name;

    ret = getaddrinfo_a (GAI_NOWAIT, &resolv->req, 1, NULL);

    if (ret)
    {
      DEBUG_PRINTF ("Panic - resolv getaddrinfo_a error %s", gai_strerror (ret));
      list_remove (&resolv_list, resolv, resolv_cleanup, __func__);
      return;
    }

    resolv_poll (resolv);
  }
}

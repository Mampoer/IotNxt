/*
 * https.c
 *
 *  Created on: 26 Jan 2017
 *      Author: hein
 */

#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/socket.h>

#include "io.h"
#include "utils.h"
#include "http_parser.h"

#define DEBUG_LOG(...) LOG( __SHORT_FILE__, __LINE__, __VA_ARGS__ );

list_t *ip_block_list = NULL;

static void http_conn_cleanup (IO_Handle_t *IO_Handle)
{
  if (IO_Handle)
  {
    http_conn_t *http_conn = (http_conn_t *)IO_Handle;

    if (http_conn->endpoint_cleanup)  http_conn->endpoint_cleanup (http_conn->endpoint_handle);
    if (http_conn->endpoint_handle)   free (http_conn->endpoint_handle);
    if (http_conn->http_param_list)   list_clear (&http_conn->http_param_list, cleanup_http_param_list_item, NULL);
    if (http_conn->url_decoded_path)  free (http_conn->url_decoded_path);
    if (http_conn->useragent)         free (http_conn->useragent);

    memset ((void *)http_conn + sizeof(IO_Handle_t), 0, sizeof(http_conn_t) - sizeof(IO_Handle_t));

    //DEBUG_PRINTF("(%s:%d) cleaned up\n", IO_Handle->ip, IO_Handle->fd);
  }
}


static int http_conn_io (IO_Handle_t *IO_Handle)
{
  int ret = 0;

  if (IO_Handle)
  {
    http_conn_t *http_conn = (http_conn_t *)IO_Handle;

    //DEBUG_PRINTF("(%s:%d) %d to process", http_conn->IO_Handle->remote_ip, http_conn->IO_Handle->fd, http_conn->IO_Handle->rx_index);

    // never send from anything in the call tree as it may destoy the socket in case of BROKEN PIPE and remove the conn
    if (IO_Handle->rx_index)
    {
      ret = http_parse_request  ( http_conn
                                , (char *) IO_Handle->rx_buf
                                , IO_Handle->rx_index);
    }
  }

  return ret;
}

void init_http_conn (IO_Handle_t *IO_Handle)
{
  if (IO_Handle)
  {
    IO_Handle->io_cleanup   = http_conn_cleanup;
    IO_Handle->io           = http_conn_io;
  }
}


/*
 * http.c
 *
 *  Created on: 15 Jun. 2018
 *      Author: heindekock
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdlib.h>
#include <stdio.h>

#include "file_serve.h"
#include "endpoints.h"
#include "utils.h"

typedef struct http_param {
  char *param;
  char *value;
} http_param_t;

void debug_print_http_req_info (http_conn_t *http_conn)
{
  if (http_conn)
  {
    DEBUG_PRINTF("\t method is (%d) %s"        , (int)http_conn->methode_type, http_methode_text (http_conn->methode_type));
    DEBUG_PRINTF("\t url decoded %s"           , http_conn->url_decoded_path);
    DEBUG_PRINTF("\t HTTP version is 1.%d"     , http_conn->minor_version);

    DEBUG_PRINTF( "\t ----------------");
  }
}

void debug_print_http_req_headder (struct phr_header *headers, size_t num_headers)
{
  if (headers && num_headers)
  {
    for (int i = 0; i != num_headers; ++i)
    {
      DEBUG_PRINTF("\t headers: %.*s: %.*s"     , (int)headers[i].name_len
                                                , headers[i].name
                                                , (int)headers[i].value_len
                                                , headers[i].value);
    }

    DEBUG_PRINTF( "\t ----------------");
  }
}

void add_http_param_list (list_t **http_param_list, char *key, char *val)
{
  http_param_t *http_param = list_add (http_param_list, sizeof(http_param_t), "http_param");

  if (http_param)
  {
    http_param->param = strdup (key);
    http_param->value = strdup (val);
  }
}


void add_http_conn_param_list (http_conn_t *http_conn, char *key, char *val)
{
  if (http_conn)
  {
    add_http_param_list (&http_conn->http_param_list, key, val);
  }
}


char *get_http_param_list_value (list_t *http_param_list, char *param)
{
  list_t *list_walker = http_param_list;

  while (list_walker)
  {
    http_param_t *http_param = list_walk (&list_walker);

    if (http_param)
    {
      if (strcasecmp (http_param->param, param) == 0)
        return http_param->value;
    }
  }

  return NULL;
}

char *get_http_conn_param_list_value (http_conn_t *http_conn, char *param)
{
  if (http_conn)
  {
    return get_http_param_list_value (http_conn->http_param_list, param);
  }

  return NULL;
}


char *get_http_conn_user_agent (http_conn_t *http_conn)
{
  if (http_conn)
  {
    return http_conn->useragent;
  }

  return NULL;
}


void remove_http_param_list_value (list_t **http_param_list, char *param)
{
  list_t *list_walker = *http_param_list;

  while (list_walker)
  {
    http_param_t *http_param = list_walk (&list_walker);

    if (http_param)
    {
      if (strcasecmp (http_param->param, param) == 0)
        list_remove (http_param_list, http_param, NULL, NULL);
    }
  }
}


void remove_http_conn_param_list_value (http_conn_t *http_conn, char *param)
{
  if (http_conn)
  {
    remove_http_param_list_value (&http_conn->http_param_list, param);
  }
}


list_t *build_http_param_list (char *path)
{
  bool printed = false;
  list_t *http_param_list = NULL;

  if (path)
  {
    char scratch[4096];
    int index = 0;

    char *p = strchr (path, '?');

    if (p) // looks like we have params
    {
      *p = '\0';
      p++; // step over '?'
    }
    else
      p = path;

    if (*p)
    {
      char *param = NULL;
      char *value = NULL;

      //cardnumber=4658%205887%200730%207014&exp-date=08%20%2F%2020&fullName=G%20j%20horne&cvc=565&Address1=Flat%203&Address2=&PostCode=SW15%202AT&City=4%20Mercier%20Road&Email=gerthorne%40kashing.co.uk&TransactionID=2046fe22b612340617b7ca8cd302a34

      while (*p)
      {
        if (index < (sizeof(scratch) - 1))
        {
          scratch[index] = *p;
          scratch[index + 1] = '\0';
        }

        index ++;
        p ++;

        if (*p == '=')
        {
          if (index >= (sizeof(scratch) + 1))
          {
            DEBUG_PRINTF("\t over sized parameter");
          }

          param = url_decode (scratch, index);
          index = 0;
          p++;
        }

        if (*p == '&' || *p == '\0')
        {
          if (index >= (sizeof(scratch) + 1))
          {
            DEBUG_PRINTF("\t over sized value");
          }

          value = url_decode (scratch, index);
          index = 0;
          p++;

          if (param && value)
          {
            http_param_t *http_param = list_add (&http_param_list, sizeof(http_param_t), "http_param");

            if (http_param)
            {
              http_param->param = param;
              http_param->value = value;

              if (!printed)
              {
                printf ("\n");
                printed = true;
              }

              DEBUG_PRINTF("\t parameter: %-20s: %s", param, value);

              param = NULL;
              value = NULL;

              continue;
            }
          }

          if (param)
            free (param);

          if (value)
            free (value);

          param = NULL;
          value = NULL;
        }
      }

      if (param)
        free (param);

      if (value)
        free (value);

      if (http_param_list)
      {
        DEBUG_PRINTF( "\t ----------------");
      }
    }
  }

  return http_param_list;
}


void cleanup_http_param_list_item (void *userdata)
{
  http_param_t *http_param = userdata;

  if (http_param)
  {
    if (http_param->param)
      free (http_param->param);

    if (http_param->value)
      free (http_param->value);
  }
}


methode_t get_methode_type (const char *method, int method_len)
{
  if (method && method_len)
  {
    switch (method_len)
    {
      case 3:  if (method[0] == 'G')  { return METHODE_GET;     }
               if (method[0] == 'P')  { return METHODE_PUT;     } break;
      case 4:  if (method[0] == 'P')  { return METHODE_POST;    }
               if (method[0] == 'H')  { return METHODE_HEAD;    } break;
      case 5:  if (method[0] == 'P')  { return METHODE_PATCH;   } break;
      case 6:  if (method[0] == 'D')  { return METHODE_DELETE;  } break;
      case 7:  if (method[0] == 'O')  { return METHODE_OPTIONS; } break;
    }
  }

  return METHODE_UNKNOWN;
}

const char *http_methode_text (methode_t methode)
{
  switch (methode)
  {
    case METHODE_GET:     return "GET";
    case METHODE_POST:    return "POST";
    case METHODE_PUT:     return "PUT";
    case METHODE_HEAD:    return "HEAD";
    case METHODE_DELETE:  return "DELETE";
    case METHODE_PATCH:   return "PATCH";
    case METHODE_OPTIONS: return "OPTIONS";
    default:              return "UNKNOWN";
  }
}

bool http_header_connection_close (http_conn_t *http_conn)
{
  return http_conn->flags & HTTP_FLAG_CLOSE;
}

bool http_header_connection_keep_alive (http_conn_t *http_conn)
{
  return http_conn->flags & HTTP_FLAG_KEEP_ALIVE;
}


int  http_parse_request   ( http_conn_t *http_conn
                          , char        *data
                          , int         len         )
{
  if (len)
  {
//    if (len > 7)
    {
      if (http_conn->endpoint_cleanup)
      {
        DEBUG_PRINTF("(%s:%d) cleanup still exist (busy)!", http_conn->IO_Handle.ip, http_conn->IO_Handle.fd); // hope this never happens

        if (http_conn->IO_Handle.io_cleanup)
          http_conn->IO_Handle.io_cleanup (&http_conn->IO_Handle);
      }

      if (!http_conn->header_lenght)
      {
        const char *method, *path;
        struct phr_header   headers [100];
        size_t              num_headers;

        size_t method_len, path_len;

        num_headers = sizeof (headers) / sizeof (headers[0]);

        int pret = phr_parse_request ((char *)  data, len,
                                                &method,
                                                &method_len,
                                                &path,
                                                &path_len,
                                                &http_conn->minor_version,
                                                headers,
                                                &num_headers,
                                                0 ); // cannot keep a last length as the rx buf is realloced so all ref will be wrong

        if (pret > 0) // passing good, grab everything you need here as any more data will force a realloc on the rxbuf
        {
          http_conn->header_lenght = pret;
          http_conn->content_length = 0;

          http_conn->methode_type = get_methode_type (method, method_len);

          http_conn->url_decoded_path = url_decode (path, path_len);

          for (int i = 0; i != num_headers; ++i)
          {
            if (headers[i].name_len == 14)
              if (strncasecmp (headers[i].name, "Content-Length", 14) == 0)
                http_conn->content_length = atoi (headers[i].value);

            //if (http_conn->headers[i].name_len == 10)
            //  if ( strncmp(http_conn->headers[i].name, "Connection", 10) == 0 )
            //    connection_close = ~strcmp (http_conn->headers[i].value, "close");

            if (headers[i].name_len == 10)
              if (strncasecmp (headers[i].name, "user-agent", 10) == 0)
                if (!http_conn->useragent)
                  asprintf (&http_conn->useragent, "%.*s", (int)headers[i].value_len, headers[i].value);

            if (headers[i].name_len == 10)
              if (strncasecmp (headers[i].name, "Connection", 10) == 0)
              {
                if (strncasecmp (headers[i].value, "Keep-Alive", 10) == 0)
                  http_conn->flags |= HTTP_FLAG_KEEP_ALIVE;
                else if (strncasecmp (headers[i].value, "Close", 5) == 0)
                  http_conn->flags |= HTTP_FLAG_CLOSE;
              }
          }
        }
        else
        {
          //DEBUG_PRINTF("(%s:%d) Parser failed! %d: %.*s", http_conn->IO_Handle.ip, http_conn->IO_Handle.fd, pret, len, data);
        }
      }

      if (http_conn->header_lenght)
      {
        if (len >= (http_conn->header_lenght + http_conn->content_length))
        {
          int ret = http_conn->header_lenght + http_conn->content_length;

          //DEBUG_PRINTF("Complete %d of %d, (%d) %s", (http_conn->header_lenght + http_conn->content_length), len, http_conn->methode_type, http_methode_text (http_conn->methode_type));

          if (http_conn->methode_type == METHODE_GET
            || http_conn->methode_type == METHODE_POST)
          {
            if (http_conn->url_decoded_path)
            {
              http_conn->http_param_list = build_http_param_list (http_conn->url_decoded_path);

              char *payload = NULL;

              if (http_conn->content_length)
                asprintf (&payload, "%.*s", http_conn->content_length, &data[http_conn->header_lenght]);

              endpoint_check  ( http_conn
                              , http_conn->url_decoded_path
                              , payload                     );

              if (payload)
                free (payload);

              free (http_conn->url_decoded_path);

              http_conn->url_decoded_path = NULL;
            }
          }
          else
          {
            reply_forbidden (http_conn);
          }

          return ret;
        }
        else
        {
          //DEBUG_PRINTF("(%s:%d) Incomplete %d of %d: %.*s", http_conn->IO_Handle.ip, http_conn->IO_Handle.fd, len, (http_conn->header_lenght + http_conn->content_length), len, data);
        }
      }

      return 0; // dont drop to unit handler is get or post
    }

//    while ( https_conn->len >= sizeof(packet_head_t) )
//    {
//      packet_head_t *packet_head = (packet_head_t *) https_conn->data;
//      uint8_t *data = https_conn->data + sizeof(packet_head_t);
//      uint64_t start, poll_time;
//
//      if (packet_head->magic_number != UNIT_MAGIC_NUMBER)
//      {
//        DEBUG_PRINTF("(%s:%d) Magic number error %08X", https_conn->remote_ip, https_conn->fd, packet_head->magic_number);
//        https_conn->len -= 1;
//        if (https_conn->len)
//          memmove ( https_conn->data, https_conn->data + 1, https_conn->len);
//        continue;
//      }
//
//      if (packet_head->len > 1500)
//      {
//        DEBUG_PRINTF("(%s:%d) Packet len error %hd on %d", https_conn->remote_ip, https_conn->fd, packet_head->len, https_conn->fd);
//        https_conn->len = 0; // flush rx buf
//        break;
//      }
//
//      if ( https_conn->len < (sizeof(packet_head_t) + packet_head->len)) // not enough data - less than indicated packet length
//      {
//        DEBUG_PRINTF("(%s:%d) Not enough data"          , https_conn->remote_ip, https_conn->fd);
//        DEBUG_PRINTF("(%s:%d) cmd %hu"                  , https_conn->remote_ip, https_conn->fd, packet_head->cmd);
//        DEBUG_PRINTF("(%s:%d) len %hu"                  , https_conn->remote_ip, https_conn->fd, packet_head->len);
//        DEBUG_PRINTF("(%s:%d) crc %hu"                  , https_conn->remote_ip, https_conn->fd, packet_head->crc);
//        DEBUG_PRINTF("(%s:%d) magic_number 0x%08X"      , https_conn->remote_ip, https_conn->fd, packet_head->magic_number);
//        DEBUG_PRINTF("(%s:%d) received %d of %zd"       , https_conn->remote_ip, https_conn->fd, https_conn->len, (sizeof(packet_head_t) + packet_head->len));
//        break; // from while (conns[i].len >= 3)
//      }
//
//      if (packet_head->len)
//      {
//        if (packet_head->crc != CalculateCRC (data, packet_head->len))
//        {
//          DEBUG_PRINTF("(%s:%d) CRC error %04X != %04X" , https_conn->remote_ip, https_conn->fd, packet_head->crc,
//              CalculateCRC ( data, packet_head->len));
//
//          if (packet_head->len <= https_conn->len)
//            https_conn->len -= (sizeof(packet_head_t) + packet_head->len);
//          else
//            https_conn->len = 0;
//
//          if ( https_conn->len)
//            memmove ( https_conn->data, https_conn->data + (sizeof(packet_head_t) + packet_head->len),
//              https_conn->len);
//
//          continue;
//        }
//      }
//
//      start = GetUcTimeStamp ();
//
//      //    DEBUG_PRINTF("(%s:%d) Command %d", server_packet->packet_head.cmd);
//
//      Timer_Add (60 * 7, SingleShot, https_conn_timeout, https_conn);
//
//      switch (packet_head->cmd)
//      {
//        case UNIT_REPLY:  UNIT_DATA_Handler     (https_conn, data, packet_head->len);          break;
//        case UNIT_ACK:    UNIT_ACK_Handler      (https_conn, data, packet_head->len);          break;
//        case UNIT_SW1SW2: UNIT_SW1SW2_Handler   (https_conn, data, packet_head->len);          break;
//        default:
//          DEBUG_PRINTF ("Unknown command %d", packet_head->cmd);
//          https_conn->len = 0;
//          continue;
//          break; // flush rx buf
//      }
//
//      // todo asset number moved to transaction-uuid, for perm connected devices - keep a serial in tlv list
//  //    if ( https_conn->asset_number )
//  //      Timer_Remove(login_timeout, https_conn);
//
//  //        update_last_comms(https_conn);
//
//      poll_time = GetUcTimeStamp () - start;
//
//      if (poll_time > 1000000) DEBUG_PRINTF ("Panic - https_rx Slow %f", (float) poll_time / 1000000);
//
//      https_conn->len -= (sizeof(packet_head_t) + packet_head->len);
//
//      if ( https_conn->len)
//        memmove ( https_conn->data, https_conn->data + (sizeof(packet_head_t) + packet_head->len),
//          https_conn->len);
//
//    } // while (https_conn->len >= 3)
  }

  return 0;
}

int http_parse_response ( http_rsp_t  *http_rsp // we have no option but to rescan
                        , char        *rx_buf
                        , int         *rx_index)
{
  const char            *msg;
  size_t                msg_len;
  struct phr_header     headers[100];

  if (!http_rsp->headder_length) // can only be done once, the buf will be realloced and moved so no ref will be valid
  {
    //DEBUG_PRINTF("%.*s", (int)*rx_index, response);

    size_t num_headers;

    num_headers = sizeof(headers) / sizeof(headers[0]);

    int pret = phr_parse_response ( rx_buf, *rx_index,
                                    &http_rsp->minor_version,
                                    &http_rsp->status,
                                    &msg,
                                    &msg_len,
                                    headers,
                                    &num_headers,
                                    0                         );

    if (pret > 0) /* successfully parsed the request */
    {
      http_rsp->headder_length = pret;

      DEBUG_PRINTF("\t response is %d bytes long", pret);
      DEBUG_PRINTF("\t HTTP version is 1.%d"     , http_rsp->minor_version);
      DEBUG_PRINTF("\t msg is %.*s"              , (int)msg_len, msg);

      for ( int i = 0; i < num_headers; ++i)
      {
//        DEBUG_PRINTF("\t headers: %.*s: %.*s" , (int)headers[i].name_len
//                                              , headers[i].name
//                                              , (int)headers[i].value_len
//                                              , headers[i].value);

        if (headers[i].name_len == 17)
          if (strncasecmp (headers[i].name, "Transfer-Encoding", (int) headers[i].name_len) == 0)
            if (strncasecmp (headers[i].value, "chunked", (int) headers[i].value_len) == 0)
              http_rsp->chunked = true;

        if (headers[i].name_len == 14)
          if ( strncasecmp(headers[i].name, "Content-Length:", 14) == 0 )
            http_rsp->content_length = atoi (headers[i].value);
      }
    }
  }

  if (http_rsp->headder_length)
  {
    if (http_rsp->chunked)
    {
      if (*rx_index > http_rsp->headder_length)
      {
        size_t decode_len = *rx_index - http_rsp->headder_length - http_rsp->content_length;

        int pret = phr_decode_chunked (&http_rsp->decoder, rx_buf + http_rsp->headder_length + http_rsp->content_length, &decode_len);

        http_rsp->content_length += decode_len;

        if (pret > 0)
        {
          return http_rsp->headder_length + http_rsp->content_length;
        }

        if (pret == -2) // must continue - reduce the rx index
        {
          *rx_index = http_rsp->headder_length + http_rsp->content_length;
        }
      }
    }
    else
    if (http_rsp->headder_length && http_rsp->content_length) // leave after chuncked as chunk can set contentlength
    {
      if (*rx_index >= (http_rsp->headder_length + http_rsp->content_length))
      {
        return (http_rsp->headder_length + http_rsp->content_length);
      }
    }
  }

  return 0;
}


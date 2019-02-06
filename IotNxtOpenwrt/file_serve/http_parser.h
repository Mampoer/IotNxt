/*
 * parser.h
 *
 *  Created on: 15 Jun. 2018
 *      Author: heindekock
 */

#ifndef HTTP_PARSER_H_
#define HTTP_PARSER_H_

#include <stdbool.h>
#include "http.h"
#include "utils.h"
#include "picohttpparser.h"

typedef enum {
  METHODE_GET = 0,
  METHODE_POST,
  METHODE_PUT,
  METHODE_HEAD,
  METHODE_DELETE,
  METHODE_PATCH,
  METHODE_OPTIONS,
  METHODE_UNKNOWN,
} methode_t;

const char *http_methode_text (methode_t methode_type);

typedef struct http_rsp {
  int                         minor_version;
  int                         status;
  bool                        chunked;
  struct phr_chunked_decoder  decoder;
  int                         headder_length;
  int                         content_length;
} http_rsp_t;

typedef void (*http_cleanup_t)    (void *handle);

#define HTTP_FLAG_CLOSE       0x01
#define HTTP_FLAG_KEEP_ALIVE  0x02

typedef struct http_conn
{
  IO_Handle_t           IO_Handle;         // leave in first pos

  int                   header_lenght,
                        content_length;
  int                   minor_version;
  methode_t             methode_type;
  list_t                *http_param_list;
  char                  *url_decoded_path;
  char                  *useragent;
  char                  flags;

  http_cleanup_t        endpoint_cleanup;
  void                  *endpoint_handle;
} http_conn_t;

void  *find_http_conn             (void *conn_ref);
void  release_http_conn           (void *conn_ref);

int  http_parse_request   ( http_conn_t *http_conn
                          , char        *data
                          , int         len);

int  http_parse_response  ( http_rsp_t  *http_rsp
                          , char        *rx_buf
                          , int         *rx_index);

bool    http_header_connection_close        (http_conn_t *http_conn);
bool    http_header_connection_keep_alive   (http_conn_t *http_conn);

void    debug_print_http_req_info           (http_conn_t *http_conn);

void    remove_http_conn_param_list_value   (http_conn_t *http_conn, char *param);
char    *get_http_conn_param_list_value     (http_conn_t *http_conn, char *param);
void    add_http_conn_param_list            (http_conn_t *http_conn, char *param, char *val);
char    *get_http_conn_user_agent           (http_conn_t *http_conn);
void    cleanup_http_param_list_item        (void *userdata);
list_t  *build_http_param_list              (char *path);
char    *get_http_param_list_value          (list_t *http_param_list, char *param);

#endif /* HTTP_PARSER_H_ */

/*
 * file_serve.h
 *
 *  Created on: 21 Mrt. 2018
 *      Author: heindekock
 */

#ifndef FILE_SERVE_H_
#define FILE_SERVE_H_

#include "http_parser.h"
#include "utils.h"

#define HTTP_RES_ERROR         0
#define HTTP_RES_PAUSE         1
#define HTTP_RES_FATAL         2
#define HTTP_RES_USER          3
#define HTTP_RES_DATA_TOO_LONG 4
#define HTTP_RES_OK            200

#define HTTP_RES_100           100
#define HTTP_RES_CONTINUE      100
#define HTTP_RES_SWITCH_PROTO  101
#define HTTP_RES_PROCESSING    102
#define HTTP_RES_URI_TOOLONG   122

#define HTTP_RES_200           200
#define HTTP_RES_CREATED       201
#define HTTP_RES_ACCEPTED      202
#define HTTP_RES_NAUTHINFO     203
#define HTTP_RES_NOCONTENT     204
#define HTTP_RES_RSTCONTENT    205
#define HTTP_RES_PARTIAL       206
#define HTTP_RES_MSTATUS       207
#define HTTP_RES_IMUSED        226

#define HTTP_RES_300           300
#define HTTP_RES_MCHOICE       300
#define HTTP_RES_MOVEDPERM     301
#define HTTP_RES_FOUND         302
#define HTTP_RES_SEEOTHER      303
#define HTTP_RES_NOTMOD        304
#define HTTP_RES_USEPROXY      305
#define HTTP_RES_SWITCHPROXY   306
#define HTTP_RES_TMPREDIR      307

#define HTTP_RES_400           400
#define HTTP_RES_BADREQ        400
#define HTTP_RES_UNAUTH        401
#define HTTP_RES_PAYREQ        402
#define HTTP_RES_FORBIDDEN     403
#define HTTP_RES_NOTFOUND      404
#define HTTP_RES_METHNALLOWED  405
#define HTTP_RES_NACCEPTABLE   406
#define HTTP_RES_PROXYAUTHREQ  407
#define HTTP_RES_TIMEOUT       408
#define HTTP_RES_CONFLICT      409
#define HTTP_RES_GONE          410
#define HTTP_RES_LENREQ        411
#define HTTP_RES_PRECONDFAIL   412
#define HTTP_RES_ENTOOLARGE    413
#define HTTP_RES_URITOOLARGE   414
#define HTTP_RES_UNSUPPORTED   415
#define HTTP_RES_RANGENOTSC    416
#define HTTP_RES_EXPECTFAIL    417
#define HTTP_RES_IAMATEAPOT    418

#define HTTP_RES_500           500
#define HTTP_RES_SERVERR       500
#define HTTP_RES_NOTIMPL       501
#define HTTP_RES_BADGATEWAY    502
#define HTTP_RES_SERVUNAVAIL   503
#define HTTP_RES_GWTIMEOUT     504
#define HTTP_RES_VERNSUPPORT   505
#define HTTP_RES_BWEXEED       509

#define MIME_TEXT_HTML         "text/html"
#define MIME_TEXT_PLAIN        "text/plain"
#define MIME_APPLICATION_JSON  "application/json"


typedef struct http_header {
  const char *header;
  const char *value;
} http_header_t;

void add_http_header  (list_t           **http_header_list
                      , const char      *header
                      , const char      *value);

void reply_not_found  (http_conn_t      *http_conn);

void reply_forbidden  (http_conn_t      *http_conn);

void http_reply       (http_conn_t      *http_conn
                      , int             code
                      , list_t          *header_list
                      , char            *content
                      , int             content_len   );

void serve_file       (http_conn_t      *http_conn
                      , char            *file         );

void hpp_serve        (http_conn_t      *http_conn
                      , char            *query
                      , bool            debug         );

#endif /* FILE_SERVE_H_ */

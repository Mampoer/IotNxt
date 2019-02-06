/*
 * file_serve.c
 *
 *  Created on: 21 Mrt. 2018
 *      Author: heindekock
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <string.h>
#include <stdlib.h>

#include "file_serve.h"
#include "endpoints.h"
#include "utils.h"

#include "picohttpparser.h"

//A Status-line
//Zero or more header (General|Response|Entity) fields followed by CRLF
//An empty line (i.e., a line with nothing preceding the CRLF) indicating the end of the header fields
//Optionally a message-body

//S.N.  Code and Description
//1 1xx: Informational
//It means the request was received and the process is continuing.
//
//2 2xx: Success
//It means the action was successfully received, understood, and accepted.
//
//3 3xx: Redirection
//It means further action must be taken in order to complete the request.
//
//4 4xx: Client Error
//It means the request contains incorrect syntax or cannot be fulfilled.
//
//5 5xx: Server Error
//It means the server failed to fulfill an apparently valid request.
//

//https://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol
//Response message
//The response message consists of the following:
//
//A status line which includes the status code and reason message (e.g., HTTP/1.1 200 OK, which indicates that the client's request succeeded).
//Response header fields (e.g., Content-Type: text/html).
//An empty line.
//An optional message body.
//The status line and other header fields must all end with <CR><LF>. The empty line must consist of only <CR><LF> and no other whitespace.[31] This strict requirement for <CR><LF> is relaxed somewhat within message bodies for consistent use of other system linebreaks such as <CR> or <LF> alone.[33]
//

char *global_document_root = "www";

static const char *
status_code_to_str(int code)
{
  switch (code) {
    case HTTP_RES_200:            return "OK";
    case HTTP_RES_300:            return "Redirect";
    case HTTP_RES_400:            return "Bad Request";
    case HTTP_RES_NOTFOUND:       return "Not Found";
    case HTTP_RES_SERVERR:        return "Internal Server Error";
    case HTTP_RES_CONTINUE:       return "Continue";
    case HTTP_RES_FORBIDDEN:      return "Forbidden";
    case HTTP_RES_SWITCH_PROTO:   return "Switching Protocols";
    case HTTP_RES_MOVEDPERM:      return "Moved Permanently";
    case HTTP_RES_PROCESSING:     return "Processing";
    case HTTP_RES_URI_TOOLONG:    return "URI Too Long";
    case HTTP_RES_CREATED:        return "Created";
    case HTTP_RES_ACCEPTED:       return "Accepted";
    case HTTP_RES_NAUTHINFO:      return "No Auth Info";
    case HTTP_RES_NOCONTENT:      return "No Content";
    case HTTP_RES_RSTCONTENT:     return "Reset Content";
    case HTTP_RES_PARTIAL:        return "Partial Content";
    case HTTP_RES_MSTATUS:        return "Multi-Status";
    case HTTP_RES_IMUSED:         return "IM Used";
    case HTTP_RES_FOUND:          return "Found";
    case HTTP_RES_SEEOTHER:       return "See Other";
    case HTTP_RES_NOTMOD:         return "Not Modified";
    case HTTP_RES_USEPROXY:       return "Use Proxy";
    case HTTP_RES_SWITCHPROXY:    return "Switch Proxy";
    case HTTP_RES_TMPREDIR:       return "Temporary Redirect";
    case HTTP_RES_UNAUTH:         return "Unauthorized";
    case HTTP_RES_PAYREQ:         return "Payment Required";
    case HTTP_RES_METHNALLOWED:   return "Not Allowed";
    case HTTP_RES_NACCEPTABLE:    return "Not Acceptable";
    case HTTP_RES_PROXYAUTHREQ:   return "Proxy Authentication Required";
    case HTTP_RES_TIMEOUT:        return "Request Timeout";
    case HTTP_RES_CONFLICT:       return "Conflict";
    case HTTP_RES_GONE:           return "Gone";
    case HTTP_RES_LENREQ:         return "Length Required";
    case HTTP_RES_PRECONDFAIL:    return "Precondition Failed";
    case HTTP_RES_ENTOOLARGE:     return "Entity Too Large";
    case HTTP_RES_URITOOLARGE:    return "Request-URI Too Long";
    case HTTP_RES_UNSUPPORTED:    return "Unsupported Media Type";
    case HTTP_RES_RANGENOTSC:     return "Requested Range Not Satisfiable";
    case HTTP_RES_EXPECTFAIL:     return "Expectation Failed";
    case HTTP_RES_IAMATEAPOT:     return "I'm a teapot";
    case HTTP_RES_NOTIMPL:        return "Not Implemented";
    case HTTP_RES_BADGATEWAY:     return "Bad Gateway";
    case HTTP_RES_SERVUNAVAIL:    return "Service Unavailable";
    case HTTP_RES_GWTIMEOUT:      return "Gateway Timeout";
    case HTTP_RES_VERNSUPPORT:    return "HTTP Version Not Supported";
    case HTTP_RES_BWEXEED:        return "Bandwidth Limit Exceeded";
  } /* switch */

  return "UNKNOWN";
}     /* status_code_to_str */


//void debug_pars_out(char *response, int rsp_len)
//{
//  int                       minor_version;
//  int                       status;
//  const char                *msg;
//  size_t                    msg_len,
//                            num_headers;
//  struct phr_header         headers[100];
//
//  num_headers = sizeof(headers) / sizeof(headers[0]);
//
//  int pret = phr_parse_response (response,
//                                  rsp_len,
//                                  &minor_version,
//                                  &status,
//                                  &msg,
//                                  &msg_len,
//                                  headers,
//                                  &num_headers,
//                                  0 );
//
//  if ( pret > 0 ) /* successfully parsed the request */
//  {
//    DEBUG_PRINTF("\t response is %d bytes long", pret);
//    DEBUG_PRINTF("\t HTTP version is 1.%d"     , minor_version);
//    DEBUG_PRINTF("\t msg is %.*s"              , (int)msg_len, msg);
//
//    for ( int i = 0; i != num_headers; ++i)
//    {
//      DEBUG_PRINTF("\t headers: %.*s: %.*s", (int)headers[i].name_len, headers[i].name, (int)headers[i].value_len, headers[i].value);
//    }
//  }
//}

int should_keep_alive(int major, int minor, http_conn_t *http_conn)
{
  if (major > 0 && minor > 0)
  {
    if (http_header_connection_close(http_conn))
      return 0;
    else
      return 1;
  }
  else
  {
    if (http_header_connection_keep_alive(http_conn))
      return 1;
    else
      return 0;
  }

  return 0;
}

void http_reply (http_conn_t  *http_conn
                , int         code
                , list_t      *header_list
                , char        *content
                , int         content_len )
{
  if (http_conn)
  {
    const char    *content_type = NULL;
    char          res_header_buf[2048];
    int           header_len    = 0;


    // look for header parsed on incoming request

    //DEBUG_PRINTF( "==============================================================");
    //DEBUG_PRINTF("http_reply: %d %s", code, status_code_to_str (code));

    header_len = sprintf (res_header_buf, "HTTP/1.%d %d %s\r\n", http_conn->minor_version, code, status_code_to_str (code));

    /* add the proper keep-alive type headers based on http version */
    switch (http_conn->minor_version)
    {
      case 1: // http 1.1
        if (!should_keep_alive (1, http_conn->minor_version, http_conn))
            /* protocol is HTTP/1.1 but client wanted to close */
          header_len += sprintf (res_header_buf + header_len, "Connection: close\r\n");

        if (!content_len)
          header_len += sprintf (res_header_buf + header_len, "Content-Length: 0\r\n");

        break;
      case 0: // http 1.0
        if (should_keep_alive(1, http_conn->minor_version, http_conn))
            /* protocol is HTTP/1.0 and clients wants to keep established */
          header_len += sprintf (res_header_buf + header_len, "Connection: keep-alive\r\n");
          //header_len += sprintf (res_header_buf + header_len, "Connection: Keep-Alive\r\n");

        break;
    } /* switch */


    header_len += sprintf (res_header_buf + header_len, "Access-Control-Allow-Origin: *\r\n");
    header_len += sprintf (res_header_buf + header_len, "Access-Control-Request-Method: %s\r\n", http_methode_text (http_conn->methode_type));

    if ( content && content_len )
      header_len += sprintf (res_header_buf + header_len, "Content-Length: %d\r\n", content_len);

//    header_len += sprintf (res_header_buf + header_len, "Keep-Alive: timeout=5, max=100\r\n"); // dont squat here

    while (header_list)
    {
      header_len += sprintf (res_header_buf + header_len, "%s: %s\r\n", ((http_header_t *) &header_list->memory)->header, ((http_header_t *) &header_list->memory)->value);

      if (strcmp (((http_header_t *) &header_list->memory)->header, "Content-Type") == 0)
        content_type = ((http_header_t *) &header_list->memory)->value;

      header_list = header_list->next;
    }

    if (!content_type)
    {
      header_len += sprintf (res_header_buf + header_len, "Content-Type: text/plain\r\n" );
    }

    header_len += sprintf (res_header_buf + header_len, "\r\n");

    //debug_pars_out (res_header_buf, header_len);

    io_buffer_out (&http_conn->IO_Handle, (uint8_t *)res_header_buf, header_len);

    if (content && content_len)
      io_buffer_out (&http_conn->IO_Handle, (uint8_t *)content, content_len);

    release_io (&http_conn->IO_Handle);
  }
  else
    DEBUG_PRINTF("ERROR: no conn!");
}

void add_http_header (list_t **http_header_list, const char *header, const char *value)
{
  http_header_t *http_header_item = list_add (http_header_list, sizeof(http_header_t), "http header");

  if (http_header_item)
  {
    http_header_item->header = header;
    http_header_item->value = value;
  }
}

void reply_not_found (http_conn_t *http_conn)
{
  list_t *http_header_list = NULL;

  add_http_header (&http_header_list, "Content-Type"                    , "text/html" );

  http_reply (http_conn
            , HTTP_RES_NOTFOUND
            , http_header_list
            , "<html><h1>404 - Page not found</h1></html>"
            , 42);

  list_clear (&http_header_list, NULL, __func__);
}

void reply_forbidden (http_conn_t *http_conn)
{
  list_t *http_header_list = NULL;

  add_http_header (&http_header_list, "Content-Type"                    , "text/html" );

  http_reply (http_conn
            , HTTP_RES_FORBIDDEN
            , http_header_list
            , "<html><h1>403 - Forbidden</h1></html>"
            , 38);

  list_clear (&http_header_list, NULL, __func__);
}

void reply_error (http_conn_t *http_conn, char *error, char *file, int line)
{
  list_t *http_header_list = NULL;

  add_http_header (&http_header_list, "Content-Type"                    , "text/html" );

  char *buffer;

  asprintf (&buffer,  "<html><h1>400 - %s%s %s%d %s%s</h1></html>", file ? "file " : ""
                                                                  , file ?  file   : ""
                                                                  , line ? "line " : ""
                                                                  , line
                                                                  , error ? "error: " : ""
                                                                  , error ?  error    : "" );

  http_reply (http_conn
            , HTTP_RES_400
            , http_header_list
            , buffer ?         buffer   :         "<html><h1>400 - Error</h1></html>"
            , buffer ? strlen (buffer)  : strlen ("<html><h1>400 - Error</h1></html>"));

  list_clear (&http_header_list, NULL, __func__);
}

static
void serve (http_conn_t *http_conn
          , char *file)
{
  if (strstr (file, "..") || strstr (file, "./") || strstr (file, ".\\") || strstr (file, "\"") || strstr (file, "'"))
  {
    DEBUG_PRINTF("PANIC PANIC PANIC: TRAVERSAL! %s", file);
    reply_forbidden (http_conn);
  }
  else
  {
    char full_path[255] = "";
    int file_size = 0;

    if (!global_document_root)
      global_document_root = "www";

    snprintf (full_path, sizeof(full_path), "%s%s", global_document_root, file);

    char *file_buf = file_buf = read_file (full_path, &file_size, "rb");

    if (file_size && file_buf)
    {
      char *content_type = "text/html";

      for (int i = 0; i < strlen(file); i++)
      {
        if (file[i] == '.')
        {
                if (strncmp(&file[i], ".htm",   4) == 0)      content_type = "text/html";
          else  if (strncmp(&file[i], ".html",  5) == 0)      content_type = "text/html; charset=UTF-8";
          else  if (strncmp(&file[i], ".txt",   4) == 0)      content_type = "text/plain; charset=UTF-8";
          else  if (strncmp(&file[i], ".htmls", 6) == 0)      content_type = "text/html";
          else  if (strncmp(&file[i], ".jpeg",  5) == 0)      content_type = "image/jpeg";
          else  if (strncmp(&file[i], ".jpg",   4) == 0)      content_type = "image/jpeg";
          else  if (strncmp(&file[i], ".bm",    3) == 0)      content_type = "image/bmp";
          else  if (strncmp(&file[i], ".bmp",   4) == 0)      content_type = "image/bmp";
          else  if (strncmp(&file[i], ".gif",   4) == 0)      content_type = "image/gif";
          else  if (strncmp(&file[i], ".js",    3) == 0)      content_type = "application/javascript";
          else  if (strncmp(&file[i], ".json",  5) == 0)      content_type = "application/json";
          else  if (strncmp(&file[i], ".pdf",   4) == 0)      content_type = "application/pdf";
          else  if (strncmp(&file[i], ".xml",   4) == 0)      content_type = "application/xml";
          else  if (strncmp(&file[i], ".atom",  5) == 0)      content_type = "application/atom+xml";
          else  if (strncmp(&file[i], ".xhtml", 6) == 0)      content_type = "application/xhtml+xml";
          else  if (strncmp(&file[i], ".tif",   4) == 0)      content_type = "image/tiff";
          else  if (strncmp(&file[i], ".tiff",  5) == 0)      content_type = "image/tiff";
          else  if (strncmp(&file[i], ".png",   4) == 0)      content_type = "image/png";
          else  if (strncmp(&file[i], ".xml",   4) == 0)      content_type = "text/xml";
          else  if (strncmp(&file[i], ".z",     2) == 0)      content_type = "application/x-compress";
          else  if (strncmp(&file[i], ".zip",   4) == 0)      content_type = "application/zip";
          else  if (strncmp(&file[i], ".css",   4) == 0)      content_type = "text/css";
          else  if (strncmp(&file[i], ".ico",   4) == 0)      content_type = "image/x-icon";
          else  if (strncmp(&file[i], ".md",    3) == 0)      content_type = "text/markdown";
          else  if (strncmp(&file[i], ".ttf",   4) == 0)      content_type = "application/x-font-ttf";
        }
      }

      list_t *http_header_list = NULL;

      add_http_header (&http_header_list, "Content-Type"                    , content_type  );

      if (!strcasestr(file, "Test.htm"))
          DEBUG_PRINTF ("(%s:%d) Serving %s", http_conn->IO_Handle.ip, http_conn->IO_Handle.fd, file);

      http_reply  ( http_conn
                  , HTTP_RES_200
                  , http_header_list
                  , file_buf
                  , file_size);

      list_clear (&http_header_list, NULL, __func__);

//      if (strncmp (content_type, "image/", 6) != 0)
//        DEBUG_PRINTF ("FILE: %s, %d\n%.*s(END)", file, file_size, file_size, file_buf);

      free (file_buf);
    }
    else
    {
      DEBUG_PRINTF("\t %s not found", full_path);
      reply_not_found (http_conn);
    }
  }
}

void serve_file ( http_conn_t     *http_conn
                , char            *file         )
{
  if (strncmp (file, "/favicon.ico", 12) == 0)
  {
//    serve (http_conn, "/Asset/Kashing/favicon.ico");
  }
  else
  if (strncmp (file, "/Asset/", 7) == 0)
  {
    serve (http_conn, file);
  }
  else
  if (strstr (file, "/") == 0)
  {
    reply_forbidden (http_conn);
  }
  else
  {
    debug_print_http_req_info (http_conn);

    DEBUG_PRINTF ("\t unknown file: %s!", file);

    reply_forbidden (http_conn);
  }
}


/*
 * defines.h
 *
 *  Created on: 14 Apr 2017
 *      Author: hein
 */

#ifndef DEFINES_H_
#define DEFINES_H_

#define Log_dir                       "./log"
#define Log_Filename                  "./log/log.txt"

#define ONE_DAY                       (60 * 60 * 24)

#define HTTP_PORT                     30080
#define HTTPS_PORT                    30443
#define MONITOR_PORT                  30081

#include "http_parser.h"

#define SOCKET_ARRAY  Socket_t socket_arr [2] = {{0, HTTPS_PORT, init_http_conn, sizeof(http_conn_t), 1 }\
                                                ,{0, HTTP_PORT,  init_http_conn, sizeof(http_conn_t), 0 }};

#endif /* DEFINES_H_ */

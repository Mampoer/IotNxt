/*
 * endpoints.h
 *
 *  Created on: 29 Mei 2018
 *      Author: heindekock
 */

#ifndef ENDPOINTS_H_
#define ENDPOINTS_H_

#include "http_parser.h"

void endpoint_check     ( http_conn_t     *http_conn
                        , char            *path
                        , char            *payload      );

void iot_device         ( http_conn_t     *http_conn
                        , char            *payload
                        , bool            debug         );

void iot_list           ( http_conn_t     *http_conn
                        , char            *payload
                        , bool            debug         );

void iot_config         ( http_conn_t     *http_conn
                        , char            *payload
                        , bool            debug         );



#endif /* ENDPOINTS_H_ */

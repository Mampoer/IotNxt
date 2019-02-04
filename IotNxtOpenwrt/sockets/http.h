/*
 * https.h
 *
 *  Created on: 26 Jan 2017
 *      Author: hein
 */

#ifndef HTTP_H_
#define HTTP_H_

#include "io.h"

void init_http_conn (IO_Handle_t *IO_Handle);

//void unit_command                       (https_conn_t *https_conn, cmd_t command, uint8_t *data, int len);
//
//void UNIT_DATA_Handler                  (https_conn_t *https_conn, uint8_t *rx_buf, int len);
//void UNIT_ACK_Handler                   (https_conn_t *https_conn, uint8_t *rx_buf, int len);
//void UNIT_SW1SW2_Handler                (https_conn_t *https_conn, uint8_t *rx_buf, int len);

#endif /* HTTP_H_ */

/*
 * resolv.h
 *
 *  Created on: 28 Mei 2018
 *      Author: heindekock
 */

#ifndef SOCKETS_RESOLV_H_
#define SOCKETS_RESOLV_H_

typedef void (*resolv_callback_t) (void *userdata, char *addr, char *ip);

void resolv (const char *url, resolv_callback_t resolv_callback, void *userdata);

#endif /* SOCKETS_RESOLV_H_ */

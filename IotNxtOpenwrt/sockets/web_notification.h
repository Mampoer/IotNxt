/*
 * frontend_notification.h
 *
 *  Created on: 25 Oct 2017
 *      Author: root
 */

#ifndef WEB_NOTIFICATION_H_
#define WEB_NOTIFICATION_H_

#include "http_parser.h"

typedef void (*notification_callback_t) ( void *userdata, http_rsp_t *http_rsp, char *response, int len);

void do_web_hook_notification ( char                    *url
                              , char                    *data
                              , char                    *user
                              , char                    *key
                              , notification_callback_t callback
                              , void                    *userdata );

#endif /* WEB_NOTIFICATION_H_ */

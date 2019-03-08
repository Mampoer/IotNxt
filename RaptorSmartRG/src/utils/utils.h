/*
 * utils.h
 *
 *  Created on: 07 Dec 2016
 *      Author: hein
 */

#ifndef UTILS_H_
#define UTILS_H_

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include "timer.h"

typedef void (*cleanup_callback_t)(void *);

typedef struct list {
    struct list *next;
    size_t      position;
    const char  *debug;
    char        memory;
} list_t;

void *list_add    (list_t **indirect, int size, const char *debug);
void *list_walk   (list_t **indirect);
void *list_find   (list_t *list, void *item);
void list_remove  (list_t **indirect, void *blob, cleanup_callback_t cleanup_callback, const char *debug);
//void list_remove2 (list_t **indirect, list_t *list_item, cleanup_callback_t cleanup_callback, const char *debug);
void list_clear   (list_t **indirect, cleanup_callback_t cleanup_callback, const char *debug);
int  list_count   (list_t *list);

//typedef struct {
//  char  *Request;
//  char  *Data;
//  void  *arg;
//  int   Size;
//} HTTP_RETURN_DATA;

void debug_keep_alive (void *userdata);

#define __SHORT_FILE__ \
(strrchr(__FILE__,'/') \
? strrchr(__FILE__,'/')+1 \
: __FILE__ \
)

#define LINE TOSTRING(__LINE__)

#define DEBUG_PRINTF(...)    {SysLog(__SHORT_FILE__, __LINE__, __VA_ARGS__); printf("%s %-18.18s %4d: ", local_time_string(), __SHORT_FILE__, __LINE__); printf(__VA_ARGS__); putchar('\n'); fflush(stdout);}

//#ifdef _DEBUG
//#define DEBUG_PRINTF(...)    {printf("%s %-18.18s %4d: ", local_time_string(), __SHORT_FILE__, __LINE__); printf(__VA_ARGS__); putchar('\n'); fflush(stdout);}
//#else
//#define DEBUG_PRINTF(...)
//#endif


#define           display_time_string()       local_time_string()

time_t            GetUcTimeStamp              (void);

char              *local_time_string          (void);

char              *GM_TIME                    (void);
char              *LOCAL_TIME_AND_ZONE        (void);

int               ExplodeURL                  (const char *URL, char *IP, int *port, char *Path);

bool              isValidIpAddress            (const char *ipAddress);

char              *url_decode                 (const char *str, int len);

char              *read_file (char *filename, int *filesize, char *mode); // returns a string that must be freed

int               hex2bin                     (char *buf, int count);
void              bin2hex                     (uint8_t *in, int in_size, char *hex, int hex_size);


char              *basic_auth                 (char *User, char *Pass);

void              SysLog                      (const char *file, int line, const char *format, ...);

#endif /* UTILS_H_ */

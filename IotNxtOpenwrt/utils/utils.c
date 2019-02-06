/*
 * utils.c
 *
 *  Created on: 07 Dec 2016
 *      Author: hein
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif


#include <time.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stddef.h>
#include <sys/time.h>
//#include <curl/curl.h>

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>


#include "utils.h"



time_t GetUcTimeStamp ( void )
{
  struct timeval tv;

  gettimeofday ( &tv, NULL );

  return ( tv.tv_sec * 1000000 ) + tv.tv_usec;
}

char *local_time_string (void)
{
  static char buf [32];
  time_t t = time ( NULL);
  struct tm tm = *localtime(&t);

//  strftime (buf, sizeof (buf), "%y/%m/%d,%H:%M:%S", tm);

  sprintf(buf, "%04d/%02d/%02d,%02d:%02d:%02d", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);

  return (buf);
}

char *GM_TIME (void)
{
  static char buf [32];
  time_t now = time (0);
  struct tm tm = *gmtime (&now);

//    strftime(buffer, Size, "%Y-%m-%d %X UTC%z", &tstruct);
  strftime (buf, sizeof(buf), "%Y-%m-%d %X", &tm);

  return (buf);
}

char *LOCAL_TIME_AND_ZONE (void)
{
  static char buf [32];
  time_t now = time (0);
  struct tm tm = *localtime (&now);

  strftime (buf, sizeof(buf), "%Y-%m-%d %X %z", &tm);

  return (buf);
}


int ExplodeURL ( const char *URL, char *IP, int *port, char *Path )
{
  if ( sscanf ( URL, "https://%99[^:]:%i/%199[^\n]", IP, port, Path ) == 3 )        { return 1; }
  if ( sscanf ( URL, "https://%99[^/]/%199[^\n]", IP, Path ) == 2 )                 { return 1; }
  if ( sscanf ( URL, "https://%99[^:]:%i[^\n]", IP, port ) == 2 )                   { return 1; }
  if ( sscanf ( URL, "https://%99[^\n]", IP ) == 1 )                                { return 1; }
  if ( sscanf ( URL, "http://%99[^:]:%i/%199[^\n]", IP, port, Path ) == 3 )         { return 1; }
  if ( sscanf ( URL, "http://%99[^/]/%199[^\n]", IP, Path ) == 2 )                  { return 1; }
  if ( sscanf ( URL, "http://%99[^:]:%i[^\n]", IP, port ) == 2 )                    { return 1; }
  if ( sscanf ( URL, "http://%99[^\n]", IP ) == 1 )                                 { return 1; }
  if ( sscanf ( URL, "%99[^:]:%i/%199[^\n]", IP, port, Path ) == 3 )                { return 1; }
  if ( sscanf ( URL, "%99[^/]/%199[^\n]", IP, Path ) == 2 )                         { return 1; }
  if ( sscanf ( URL, "%99[^:]:%i[^\n]", IP, port ) == 2 )                           { return 1; }
  if ( sscanf ( URL, "%99[^\n]", IP ) == 1 )                                        { return 1; }

                                                                                      return 0;
}

bool isValidIpAddress(const char *ipAddress)
{
  struct sockaddr_in sa;
  int result = inet_pton(AF_INET, ipAddress, &(sa.sin_addr));
  return result != 0;
}

void *list_add (list_t **indirect, int size, const char *debug)
{
  list_t *list_item = calloc (1, sizeof(list_t) + size);
//  int i = 0;

  if (list_item)
  {
    //memset ((void *)list_item, sizeof(list_t) + size);

    list_item->debug = debug;

    while (*indirect) // list exist
    {
//      i++;
      indirect = &(*indirect)->next; // last next pointer will be null
    }

    *indirect = list_item;
    list_item->position = (size_t)list_item;
//  DEBUG_PRINTF("List_added pos %d item %s position (%zd) %zd", i, (*indirect)->debug, (size_t)(*indirect), (*indirect)->position);
    return (void *)&list_item->memory;
  }

  return NULL;
}

void list_remove (list_t **indirect, void *blob, cleanup_callback_t cleanup_callback, const char *debug)
{
  list_t *entry;
  int i = 0;

  while ( (entry = (*indirect)) ) // test list item addr agains location that indirect points to
  {
    if ( &entry->memory == blob )
    {
//      DEBUG_PRINTF("list_removed pos %d item %s", i, entry->debug);

      if (cleanup_callback)
        cleanup_callback (&entry->memory);

      (*indirect) = entry->next;
      free (entry);
      return;
    }

    i++;
    indirect = &(*indirect)->next;    // indirect points to physical addr of current next
  }

//  DEBUG_PRINTF("list_remove error %zd %s", (size_t)list_item, debug);
}

//void list_remove2 (list_t **indirect, list_t *list_item, cleanup_callback_t cleanup_callback, const char *debug)
//{
//  list_t *entry;
//  int i = 0;
//
//  while ( (entry = (*indirect)) ) // test list item addr agains location that indirect points to
//  {
//    if ( entry == list_item )
//    {
////      DEBUG_PRINTF("list_removed pos %d item %s", i, entry->debug);
//
//      if (cleanup_callback)
//        cleanup_callback (&entry->memory);
//
//      (*indirect) = entry->next;
//      free (entry);
//      return;
//    }
//
//    i++;
//    indirect = &(*indirect)->next;    // indirect points to physical addr of current next
//  }
//
//  DEBUG_PRINTF("list_remove error %zd %s", (size_t)list_item, debug);
//}

void list_clear (list_t **indirect, cleanup_callback_t cleanup_callback, const char *debug)
{
  list_t *entry;

  while ( (entry = (*indirect)) ) // test list item addr agains location that indirect points to
  {
//      DEBUG_PRINTF("list_removed pos %d item %s", i, entry->debug);

    if (cleanup_callback)
      cleanup_callback (&entry->memory);

    (*indirect) = entry->next;
    free (entry);
  }
}

void *list_walk (list_t **indirect)
{
  void *ret = NULL;
  if ( (*indirect) ) // test list item addr agains location that indirect points to
  {
    ret = &(*indirect)->memory;
    *indirect = (*indirect)->next;    // indirect points to physical addr of current next
  }
  return ret;
}

void *list_find (list_t *list, void *item)
{
  while (list)
  {
    if (&list->memory == item)
      return &list->memory;
    list = list->next;
  }

  return NULL;
}

int list_count (list_t *list)
{
  int count = 0;

  while (list)
  {
    count++;
    list = list->next;
  }

  return count;
}


char from_hex(char ch)
{
  return isdigit(ch) ? ch - '0' : tolower(ch) - 'a' + 10;
}

/* Returns a url-decoded version of str */
/* IMPORTANT: be sure to free() the returned string after use */
char *url_decode (const char *str, int len)
{
  char *buffer = NULL;

  if ( str )
  {
    FILE *file;
    size_t size;

    /* Open a stream that writes into a malloc'd buffer that is expanded as
     necessary.  *BUFLOC and *SIZELOC are updated with the buffer's location
     and the number of characters written on fflush or fclose.  */
    file = open_memstream ( &buffer, &size );

    if ( file )
    {
      while (*str && len)
      {
        if (*str == '%')
        {
          if (str[1] && str[2])
          {
            fputc ( from_hex (str[1]) << 4 | from_hex (str[2]), file );
            str += 2;
            len -= 2;
          }
        }
        else if (*str == '+')
        {
          fputc ( ' ', file );
        }
        else
        {
          fputc ( *str, file );
        }

        str++;
        len--;
      }

      fputc ( '\0', file );

      fclose ( file );
    }
  }

  return buffer;
}


char *read_file (char *filename, int *filesize, char *mode) // returns a string that must be freed
{
  FILE *file = fopen (filename, mode);
  long fsize = 0;
  char *string = NULL;

  if (file)
  {
    fseek (file, 0, SEEK_END);
    fsize = ftell (file);
    fseek (file, 0, SEEK_SET);

    string = malloc (fsize + 1);

    if (string)
    {
      if (fread (string, fsize, 1, file) > 0)
      {
        string[fsize] = '\0';
      }
      else
      {
        fsize = 0;
      }
    }
    else
    {
      fsize = 0;
    }

    fclose (file);
  }
  else
  {
    fsize = 0;
    return NULL;
  }

  *filesize = fsize;

  return string;
}

int hex2bin (char *buf, int count)
{
  uint8_t *p1;
  uint8_t *p2;
  uint8_t bin;
  int n;
  uint8_t offset;

  if (count % 2) {
    return 0;
  }

  p1 = (uint8_t *)buf;
  p2 = (uint8_t *)buf;
  bin = 0;
  for (n = 0; n < count; n++) {
    offset = 0;
    if (*p1 >= '0' && *p1 <= '9') offset = '0';
    if (*p1 >= 'A' && *p1 <= 'F') offset = 'A' - 10;
    if (*p1 >= 'a' && *p1 <= 'f') offset = 'a' - 10;
    if (offset == 0) {
      return 0;
    }
    bin <<= 4;
    bin += (*p1 - offset);
    p1++;
    if (n % 2) {
      *p2++ = bin;
      bin = 0;
    }
  }
  return 1;
}

void bin2hex (uint8_t *in, int in_size, char *hex, int hex_size)
{
  int in_idx = 0, out_idx = 0;

  while ( in_idx < in_size )
  {
    if ( out_idx < (hex_size - 3) )
    {
      sprintf(&hex[out_idx], "%02X", (int)in[in_idx]);
      out_idx += 2;
    }

    in_idx++;
  }
}

/**
 * Base64 index table.
 */

static const char b64_table[] = {
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
  'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
  'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
  'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
  'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
  'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
  'w', 'x', 'y', 'z', '0', '1', '2', '3',
  '4', '5', '6', '7', '8', '9', '+', '/'
};

char *b64_encode (const unsigned char *src, size_t len)
{
  int i = 0;
  int j = 0;
  char *enc = NULL;
  size_t size = 0;
  unsigned char buf[4];
  unsigned char tmp[3];

  // alloc
  enc = (char *) malloc(1);
  if (NULL == enc) { return NULL; }

  // parse until end of source
  while (len--)
  {
    // read up to 3 bytes at a time into `tmp'
    tmp[i++] = *(src++);

    // if 3 bytes read then encode into `buf'
    if (3 == i)
    {
      buf[0] = (tmp[0] & 0xfc) >> 2;
      buf[1] = ((tmp[0] & 0x03) << 4) + ((tmp[1] & 0xf0) >> 4);
      buf[2] = ((tmp[1] & 0x0f) << 2) + ((tmp[2] & 0xc0) >> 6);
      buf[3] = tmp[2] & 0x3f;

      // allocate 4 new byts for `enc` and
      // then translate each encoded buffer
      // part by index from the base 64 index table
      // into `enc' unsigned char array
      enc = (char *) realloc(enc, size + 4);
      for (i = 0; i < 4; ++i)
      {
        enc[size++] = b64_table[buf[i]];
      }

      // reset index
      i = 0;
    }
  }

  // remainder
  if (i > 0)
  {
    // fill `tmp' with `\0' at most 3 times
    for (j = i; j < 3; ++j)
    {
      tmp[j] = '\0';
    }

    // perform same codec as above
    buf[0] = (tmp[0] & 0xfc) >> 2;
    buf[1] = ((tmp[0] & 0x03) << 4) + ((tmp[1] & 0xf0) >> 4);
    buf[2] = ((tmp[1] & 0x0f) << 2) + ((tmp[2] & 0xc0) >> 6);
    buf[3] = tmp[2] & 0x3f;

    // perform same write to `enc` with new allocation
    for (j = 0; (j < i + 1); ++j)
    {
      enc = (char *) realloc(enc, size + 1);
      enc[size++] = b64_table[buf[j]];
    }

    // while there is still a remainder
    // append `=' to `enc'
    while ((i++ < 3))
    {
      enc = (char *) realloc(enc, size + 1);
      enc[size++] = '=';
    }
  }

  // Make sure we have enough space to add '\0' character at end.
  enc = (char *) realloc (enc, size + 1);
  enc[size] = '\0';

  return enc;
}

unsigned char *b64_decode_ex (const char *src, size_t len, size_t *decsize)
{
  int i = 0;
  int j = 0;
  int l = 0;
  size_t size = 0;
  unsigned char *dec = NULL;
  unsigned char buf[3];
  unsigned char tmp[4];

  // alloc
  dec = (unsigned char *) malloc (1);
  if (NULL == dec)
  {
    return NULL;
  }

  // parse until end of source
  while (len--)
  {
    // break if char is `=' or not base64 char
    if ('=' == src[j])
    {
      break;
    }
    if (!(isalnum (src[j]) || '+' == src[j] || '/' == src[j]))
    {
      break;
    }

    // read up to 4 bytes at a time into `tmp'
    tmp[i++] = src[j++];

    // if 4 bytes read then decode into `buf'
    if (4 == i)
    {
      // translate values in `tmp' from table
      for (i = 0; i < 4; ++i)
      {
        // find translation char in `b64_table'
        for (l = 0; l < 64; ++l)
        {
          if (tmp[i] == b64_table[l])
          {
            tmp[i] = l;
            break;
          }
        }
      }

      // decode
      buf[0] = (tmp[0] << 2) + ((tmp[1] & 0x30) >> 4);
      buf[1] = ((tmp[1] & 0xf) << 4) + ((tmp[2] & 0x3c) >> 2);
      buf[2] = ((tmp[2] & 0x3) << 6) + tmp[3];

      // write decoded buffer to `dec'
      dec = (unsigned char *) realloc (dec, size + 3);
      if (dec != NULL)
      {
        for (i = 0; i < 3; ++i)
        {
          dec[size++] = buf[i];
        }
      }
      else
      {
        return NULL;
      }

      // reset
      i = 0;
    }
  }

  // remainder
  if (i > 0)
  {
    // fill `tmp' with `\0' at most 4 times
    for (j = i; j < 4; ++j)
    {
      tmp[j] = '\0';
    }

    // translate remainder
    for (j = 0; j < 4; ++j)
    {
      // find translation char in `b64_table'
      for (l = 0; l < 64; ++l)
      {
        if (tmp[j] == b64_table[l])
        {
          tmp[j] = l;
          break;
        }
      }
    }

    // decode remainder
    buf[0] = (tmp[0] << 2) + ((tmp[1] & 0x30) >> 4);
    buf[1] = ((tmp[1] & 0xf) << 4) + ((tmp[2] & 0x3c) >> 2);
    buf[2] = ((tmp[2] & 0x3) << 6) + tmp[3];

    // write remainer decoded buffer to `dec'
    dec = (unsigned char *) realloc (dec, size + (i - 1));
    if (dec != NULL)
    {
      for (j = 0; (j < i - 1); ++j)
      {
        dec[size++] = buf[j];
      }
    }
    else
    {
      return NULL;
    }
  }

  // Make sure we have enough space to add '\0' character at end.
  dec = (unsigned char *) realloc (dec, size + 1);
  if (dec != NULL)
  {
    dec[size] = '\0';
  }
  else
  {
    return NULL;
  }

  // Return back the size of decoded string if demanded.
  if (decsize != NULL)
  {
    *decsize = size;
  }

  return dec;
}

unsigned char *b64_decode (const char *src, size_t len)
{
  return b64_decode_ex (src, len, NULL);
}


char *basic_auth (char *User, char *Pass)
{
  char *ret = NULL;
  unsigned char *buffer;

  int len = asprintf ((char **)&buffer, "%s:key-%s", User, Pass);

  if (buffer)
  {
    if (len)
      ret = b64_encode (buffer, len);

    free (buffer);
  }

  return ret;
}




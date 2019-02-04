/*
 * io.h
 *
 *  Created on: 06 Dec 2016
 *      Author: hein
 */

#ifndef IO_LOOP_H_
#define IO_LOOP_H_

#ifdef __linux__
#include <sys/epoll.h>
#else
#include <sys/event.h>
#endif

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>

/* Obtain the return value of an SSL operation and convert into a simplified
 * error code, which is easier to examine for failure. */
enum sslstatus { SSLSTATUS_OK, SSLSTATUS_WANT_IO, SSLSTATUS_FAIL};

//typedef void (*io_timed_function) (void *arg);

typedef struct IO_Handle {
  int               rx_index;
  int               tx_index;
  uint8_t           *rx_buf;
  uint8_t           *tx_buf;

  int               fd;
  char              *ip;

  SSL               *ssl;

  BIO               *rbio; /* SSL reads from, we write to. */
  BIO               *wbio; /* SSL writes to, we read from. */

  int               idle_time;

  int               (*io)           (struct IO_Handle *IO_Handle);
  void              (*io_cleanup)   (struct IO_Handle *IO_Handle);
} IO_Handle_t;

typedef struct {
  int               fd;
  int               port;
  void              (*conn_init)(IO_Handle_t *IO_Handle);
  int               size;
  int               ssl;
} Socket_t;

#define VALID_IO_KEY    0xF5A050AF

extern int epoll_fd;

void  init_sockets    (void);
void  close_sockets   (void);
void  socket_accept   (void *conn);

void  epoll_add       (int fd, void *ptr);
void  epoll_remove    (int fd);

void  check_events    (void);

void            io_poll           (const char *caller);
IO_Handle_t     *find_io          (void *conn_ref);
void            release_io        (IO_Handle_t *IO_Handle);
void            io_buffer_out     (IO_Handle_t *IO_Handle, uint8_t *reply, int len);
void            *io_connect       (const char *ip, int port, int use_ssl, int idle_time, int size);

#endif /* IO_LOOP_H_ */

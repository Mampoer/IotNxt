/*
 * io.c
 *
 *  Created on: 06 Dec 2016
 *      Author: hein
 */

#include <stdint.h>
#include <stdbool.h>

#include <stdlib.h>
#include <string.h>

#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <netdb.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include "io.h"

#include "timer.h"
#include "utils.h"

#include "defines.h"

//**********************************************************************************
SOCKET_ARRAY

//**********************************************************************************
list_t *io_list = NULL;

static int allocated_items_of_mem = 0;

//**********************************************************************************
void open_socket (void *UserData);

//**********************************************************************************
int pri_port = 0, sec_port = 0;

int epoll_fd = -1;

struct epoll_event *events = NULL;

uint32_t max_events = 0;

//**********************************************************************************
void init_sockets (void)
{
  int i;

  if (pri_port)
    socket_arr[0].port = pri_port;

  if (sec_port)
    socket_arr[1].port = sec_port;

  for (i = 0; i < (sizeof(socket_arr) / sizeof(Socket_t)); i++)
    Timer_Add (1, SingleShot, open_socket, &socket_arr[i]);
}

//**********************************************************************************
void close_sockets (void)
{
  int i;

  for (i = 0; i < (sizeof(socket_arr) / sizeof(Socket_t)); i++)
  {
    if (socket_arr[i].fd >= 0)
    {
      close (socket_arr[i].fd);
      socket_arr[i].fd = -1;
      DEBUG_PRINTF("UnListening on %d", socket_arr[i].port);

      // todo: clear list

//      if ( socket_arr [ i ].conn_close_all )
//        socket_arr [ i ].conn_close_all();
    }
  }

  close ( epoll_fd );
}

////**********************************************************************************
//void time_check_call(io_timed_function func, void *arg, char *debug)
//{
//  uint64_t call_time = GetUcTimeStamp();
//  func(arg);
//  call_time = GetUcTimeStamp() - call_time;
////  if (call_time > 3000000) DEBUG_PRINTF("Slow function %s running %f", debug, (float)call_time/1000000);
//}

//**********************************************************************************
static int make_socket_non_blocking (int sfd)
{
  int flags, s;

  flags = fcntl (sfd, F_GETFL, 0);

  if (flags == -1)
  {
    //perror ("fcntl");
    DEBUG_PRINTF("%s fcntl: %s", __func__, strerror(errno));
    return -1;
  }

  flags |= O_NONBLOCK;
  s = fcntl (sfd, F_SETFL, flags);

  if (s == -1)
  {
    //perror ("fcntl");
    DEBUG_PRINTF("%s fcntl: %s", __func__, strerror(errno));
    return -1;
  }

  return 0;
}

//**********************************************************************************
int
make_tcp_listen_socket_deferred(int sock)
{
  int one = 1;

  /* TCP_DEFER_ACCEPT tells the kernel to call defer accept() only after data
   * has arrived and ready to read */
  return setsockopt(sock, IPPROTO_TCP, TCP_DEFER_ACCEPT, &one,
    (int)sizeof(one));

  return 0;
}

//**********************************************************************************
int
make_socket_closeonexec(int fd)
{
  int flags;
  if ((flags = fcntl(fd, F_GETFD, NULL)) < 0) {
    return -1;
  }
  if (!(flags & FD_CLOEXEC)) {
    if (fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == -1) {
      return -1;
    }
  }

  return 0;
}

//**********************************************************************************
static int create_and_bind (int port)
{
  int sock, ret, on;
  struct sockaddr_in servaddr;
  memset (&servaddr, 0, sizeof(servaddr));

  /* Allow connections from any available interface */
  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = htonl ( INADDR_ANY);
  servaddr.sin_port = htons (port);

  /* Create a new stream (TCP) socket */
  sock = socket (AF_INET, SOCK_STREAM, 0);

  if (sock == -1)
  {
    DEBUG_PRINTF("Could not create socket: %s", strerror(errno));
    return -1;
  }

  /* Enable address reuse */
  on = 1;

  setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
//  setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (int[]) {1}, sizeof(int));
//  setsockopt(sock, IPPROTO_TCP, TCP_QUICKACK, (int[]) {1}, sizeof(int));

  /* Bind to the address (interface/port) */
  ret = bind (sock, (struct sockaddr *) &servaddr, sizeof(servaddr));

  if (ret == 0)
    return sock; // We managed to bind successfully!

  close (sock);

  DEBUG_PRINTF("Could not bind to port %d", port);
  return -1;
}

//**********************************************************************************
void open_socket (void *UserData)
{
  Socket_t *Socket = UserData;
//  struct epoll_event event;

  Socket->fd = create_and_bind (Socket->port);

  if (Socket->fd == -1)
  {
    Timer_Add ( 15, SingleShot, &open_socket, Socket );
    //if ( Socket->port == Rem_Socket.port ) monitor_kill_other_session(Socket->port);
    return;
  }

  if (make_socket_non_blocking (Socket->fd) == -1)
  {
    close (Socket->fd);
    Socket->fd = -1;
    Timer_Add (15, SingleShot, &open_socket, Socket);
    return;
  }

  if (listen (Socket->fd, SOMAXCONN) == -1)
  {
    //perror("listen");
    DEBUG_PRINTF("%s listen: %s", __func__, strerror(errno));
    close (Socket->fd);
    Socket->fd = -1;
    Timer_Add (15, SingleShot, &open_socket, Socket);
  }

  epoll_add (Socket->fd, Socket);

//  event.data.ptr = Socket;
//  event.events = EPOLLIN | EPOLLET;  // edge triggered notify of data in
//  if ( epoll_ctl ( epoll_fd, EPOLL_CTL_ADD, Socket->fd, &event ) == -1 )
//  {
//    //perror("epoll_ctl");
//    DEBUG_PRINTF( "%s epoll_ctl: %s", __func__, strerror(errno) );
//    close ( Socket->fd );
//    Socket->fd = -1;
//    Timer_Add ( 15, SingleShot, &open_socket, Socket );
//  }

  DEBUG_PRINTF( "Listening on %d", Socket->port );
}

//**********************************************************************************
static void io_cleanup (void *userdata)
{
  if (userdata)
  {
    IO_Handle_t *IO_Handle = userdata;

    allocated_items_of_mem--;

    //DEBUG_PRINTF("(%s:%d) %s (%d)", conn->IO_Handle->remote_ip, conn->IO_Handle->fd, __func__, allocated_items_of_mem);

    if (IO_Handle->io_cleanup)
    {
      IO_Handle->io_cleanup (IO_Handle);
      IO_Handle->io_cleanup = NULL;
    }

    if (IO_Handle->ssl)
    {
      SSL_free (IO_Handle->ssl);
      IO_Handle->ssl = NULL;
    }

    if (IO_Handle->fd > 0)
    {
      epoll_remove (IO_Handle->fd);
      close (IO_Handle->fd);
    }

    Timer_Cleanup (IO_Handle);

    if (IO_Handle->rx_buf)   free (IO_Handle->rx_buf);
    if (IO_Handle->tx_buf)   free (IO_Handle->tx_buf);
    if (IO_Handle->ip    )   free (IO_Handle->ip    );


//    memset (conn, 0, sizeof(conn_t));
  }
}

//**********************************************************************************
static void io_add_raw (IO_Handle_t *IO_Handle, uint8_t *reply, int len)
{
  if (IO_Handle)
  {
    IO_Handle->tx_buf = realloc (IO_Handle->tx_buf, IO_Handle->tx_index + len);

    if (IO_Handle->tx_buf)
    {
      memcpy (IO_Handle->tx_buf + IO_Handle->tx_index, reply, len);
      IO_Handle->tx_index += len;
      //DEBUG_PRINTF("(%s:%d) adding to send %d, total %d", IO_Handle->ip, IO_Handle->fd, len, IO_Handle->tx_index);
    }
  }
}

//**********************************************************************************
static void bio_read (IO_Handle_t *IO_Handle)
{
  if (IO_Handle)
  {
    uint8_t buf [16 * 1024];

    while (1)
    {
      int n = BIO_read (IO_Handle->wbio, buf, sizeof(buf));

      if (n > 0)
        io_add_raw (IO_Handle, buf, n);
      else
      {
        if (!BIO_should_retry (IO_Handle->wbio))
        {
          DEBUG_PRINTF ("BIO READ ERROR %d: %s", n, ERR_reason_error_string (ERR_get_error()));
        }

        break;
      }
    }
  }
}

//**********************************************************************************
static void io_shutdown (IO_Handle_t *IO_Handle)
{
  if (IO_Handle)
  {
    //DEBUG_PRINTF ("Shutting down!");

    if (IO_Handle->ssl)
    {
      int err = SSL_shutdown (IO_Handle->ssl);

      if (err == 1)
      {
        //DEBUG_PRINTF ("SSL Shutdown success!");
      }
      else
      {
        int err1 = SSL_get_error (IO_Handle->ssl, err);

        switch (err1)
        {
          case SSL_ERROR_WANT_WRITE:
          case SSL_ERROR_WANT_READ:
            bio_read (IO_Handle);
            return;
          default:
            DEBUG_PRINTF ("SSL Shutdown error %d, %s!", err1, ERR_reason_error_string (ERR_get_error()));
            break;
        }
      }
    }

    list_remove (&io_list, IO_Handle, io_cleanup, NULL);
  }
}

//**********************************************************************************
static void io_close (IO_Handle_t *IO_Handle)
{
  if (IO_Handle)
  {
    //DEBUG_PRINTF ("(%s:%d) closing", IO_Handle->remote_ip, IO_Handle->fd);

    if (IO_Handle->ssl)
    {
      io_shutdown (IO_Handle);
      return;
    }

    list_remove (&io_list, IO_Handle, io_cleanup, NULL);
  }
}

//**********************************************************************************
static void io_timeout (void *userdata)
{
  IO_Handle_t *IO_Handle = list_find (io_list, userdata);

  if (IO_Handle)
  {
    DEBUG_PRINTF ("(%s:%d) timeout", IO_Handle->ip, IO_Handle->fd);

//    if (IO_Handle->ssl)
//    {
//      BIO_reset (IO_Handle->rbio);
//      BIO_reset (IO_Handle->wbio);
//    }

    io_close (IO_Handle);
  }
}

//**********************************************************************************
void socket_accept (void *ptr)
{
  Socket_t *Socket = ptr;

  while (1)
  {
    struct sockaddr in_addr;
    socklen_t in_len;
    int infd;

    in_len = sizeof in_addr;
    infd = accept (Socket->fd, &in_addr, &in_len);
    if (infd == -1)
    {
      if (( errno == EINTR) || ( errno == EAGAIN) || ( errno == EWOULDBLOCK))
      { // We have processed all incoming connections. */
        break; // from while(1)
      }
      else
      {
        //perror("accept");
        DEBUG_PRINTF("%s accept: %s", __func__, strerror(errno))
        close (Socket->fd);
        Socket->fd = -1;
        Timer_Add (15, SingleShot, &open_socket, Socket);
        break; // from while(1)
      }
    }

    // Make the incoming socket non-blocking and add it to the list of fds to monitor. */
    if (make_socket_non_blocking (infd) == -1)
    {
      close (infd);
      break; // from while(1)
    }

    char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];

    if (getnameinfo (&in_addr, in_len, hbuf, sizeof hbuf, sbuf, sizeof sbuf, NI_NUMERICHOST | NI_NUMERICSERV) == 0)
    {
      //DEBUG_PRINTF("Accepted conn on fd %d (host=%s:%d,%s)", infd, hbuf, Socket->port, sbuf)
    }

    make_socket_closeonexec (infd);

    list_t *list_walker = io_list;

    int ip_count = 0;
    int conn_count = 0;

    while (list_walker)
    {
      IO_Handle_t *IO_Handle = list_walk (&list_walker);

      if  (IO_Handle->fd == infd) // oops - we recycled a used fd - do something
      {
        DEBUG_PRINTF ("(%s:%d) %s duplicate fd found", IO_Handle->ip, IO_Handle->fd, __func__);
        list_remove (&io_list, IO_Handle, io_cleanup, __func__);
      }
      else
      if (strcmp (hbuf, IO_Handle->ip) == 0)
      {
        ip_count++;
      }

      conn_count++;
    }

    //  else
    //  {
    //    DEBUG_PRINTF("MAX IP COUNT (%d) REACHED for %s", ip_count, addr);
    //    alert("DOS from %s", addr);
    //  }

    IO_Handle_t *IO_Handle = list_add (&io_list, Socket->size, "conn in");

    if (IO_Handle)
    {
      allocated_items_of_mem++;

      IO_Handle->fd = infd;

      IO_Handle->ip = strdup (hbuf);

      Timer_Add (3 * ONE_MINUTE, SingleShot, io_timeout, IO_Handle); // 3 minute squating time allowed

      if (Socket->conn_init)
      {
        Socket->conn_init (IO_Handle);
      }

      if (Socket->ssl)
      {
        extern SSL_CTX *server_ctx;

        if (server_ctx)
        {
          /* ----------------------------------------------- */
          /* TCP connection is ready. Do server side SSL. */

          IO_Handle->rbio = BIO_new (BIO_s_mem ());
          IO_Handle->wbio = BIO_new (BIO_s_mem ());

      //      BIO_set_callback(conn->IO_Handle->rbio, bio_dump_callback);
      //      BIO_set_callback(conn->IO_Handle->wbio, bio_dump_callback);
      //      BIO_set_callback_arg(conn->IO_Handle->rbio, (char *)conn);
      //      BIO_set_callback_arg(conn->IO_Handle->wbio, (char *)conn);

          IO_Handle->ssl = SSL_new (server_ctx);

          if (IO_Handle->ssl)
          {
            //DEBUG_PRINTF("(%s:%d) SSL!", conn->IO_Handle->remote_ip, conn->IO_Handle->fd );

      //        SSL_set_tlsext_debug_callback (conn->IO_Handle->ssl, tlsext_cb);
      //        SSL_set_tlsext_debug_arg      (conn->IO_Handle->ssl, NULL);
      //
      //        SSL_set_generate_session_id (conn->IO_Handle->ssl, gen_session_id_callback);

            SSL_set_quiet_shutdown (IO_Handle->ssl, 1);

            SSL_set_accept_state(IO_Handle->ssl); /* sets ssl to work in server mode. */

            SSL_set_bio (IO_Handle->ssl, IO_Handle->rbio, IO_Handle->wbio);
          }
          else
          {
            ERR_print_errors_fp (stderr);
            list_remove (&io_list, IO_Handle, io_cleanup, __func__);
            return;
          }
        }
      }

      int iSocketOption = 0;
      socklen_t iSocketOptionLen = sizeof(int);
      int sock_buf_size = 625000;
      int on = 1;

      setsockopt (infd, SOL_SOCKET, SO_SNDBUF, (char *) &sock_buf_size, sizeof(sock_buf_size));
      setsockopt (infd, SOL_SOCKET, SO_RCVBUF, (char *) &sock_buf_size, sizeof(sock_buf_size));

      setsockopt (infd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on));

      getsockopt (infd, IPPROTO_TCP, TCP_NODELAY, (char *) &iSocketOption, &iSocketOptionLen);
      iSocketOption = 1;
      setsockopt (infd, IPPROTO_TCP, TCP_NODELAY, (char *) &iSocketOption, iSocketOptionLen);

      //DEBUG_PRINTF("(%s:%d) New http connection (same ip %d) total %d (mem %d)!", conn->IO_Handle->remote_ip, conn->IO_Handle->fd, ip_count, conn_count, allocated_items_of_mem);

      IO_Handle->idle_time = ONE_MINUTE * 15;

      epoll_add (IO_Handle->fd, IO_Handle);
    }
  }
}


//**********************************************************************************
bool Accept (void *mempos)
{
  int i;

  // is pointer = to lis sock
  for ( i = 0; i < ( sizeof ( socket_arr ) / sizeof(Socket_t) ); i ++ )
  {
    if ( mempos == &socket_arr [ i ] )
    {
      socket_accept ( mempos );
      return true;
    }
  }

  return false;
}


//**********************************************************************************
static enum sslstatus get_sslstatus (SSL* ssl, int n)
{
  int err = SSL_get_error (ssl, n);

  switch (err)
  {
    case SSL_ERROR_NONE:
      return SSLSTATUS_OK;
    case SSL_ERROR_WANT_WRITE:
    case SSL_ERROR_WANT_READ:
      return SSLSTATUS_WANT_IO;
    case SSL_ERROR_ZERO_RETURN:
      DEBUG_PRINTF ("SSL EOF %d: %s", err, ERR_reason_error_string (ERR_get_error()));
      return SSLSTATUS_FAIL;
    case SSL_ERROR_SYSCALL:
    default:
      DEBUG_PRINTF ("SSL ERROR %d: %s", err, ERR_reason_error_string (ERR_get_error()));
      return SSLSTATUS_FAIL;
  }
}


//**********************************************************************************
static void check_cert (IO_Handle_t *IO_Handle)
{
  if (IO_Handle)
  {
    ERR_clear_error();
    /* Get client's certificate (note: beware of dynamic allocation) - opt */
    X509 *cert = SSL_get_peer_certificate (IO_Handle->ssl);

    /* Get the cipher - opt */
    //DEBUG_PRINTF("(%s:%d) SSL connection using %s", conn->IO_Handle->remote_ip, conn->IO_Handle->fd, SSL_get_cipher(conn->IO_Handle->ssl));

    if (cert != NULL)
    {
      char* str = X509_NAME_oneline (X509_get_subject_name (cert), 0, 0);

      if (str)
      {
        DEBUG_PRINTF("(%s:%d) certificate: subject: %s", IO_Handle->ip, IO_Handle->fd, str);
        OPENSSL_free(str);

        str = X509_NAME_oneline (X509_get_issuer_name (cert), 0, 0);

        if (str)
        {
          DEBUG_PRINTF("(%s:%d) issuer: %s", IO_Handle->ip, IO_Handle->fd, str);
          OPENSSL_free(str);

          /* We could do all sorts of certificate verification stuff here before
           deallocating the certificate. */
        }
      }

      X509_free (cert);
    }
    else
    {
      //DEBUG_PRINTF("(%s:%d) Client does not have certificate", conn->IO_Handle->remote_ip, conn->IO_Handle->fd);
    }
  }
}


//**********************************************************************************
// carefull - a broken pipe can destoy this conn and remove it from the list, try to only call from event handlers
// outside functions like db callback wants to send it should oly que for HTTP_poll
static void io_send (IO_Handle_t *IO_Handle)
{
  if (IO_Handle)
  {
    if ((IO_Handle->fd > 0) && (IO_Handle->tx_index > 0))
    {
      int num_sent = send (IO_Handle->fd, IO_Handle->tx_buf, IO_Handle->tx_index, 0);

      if (num_sent > 0)
      {
        IO_Handle->tx_index -= num_sent;

        //DEBUG_PRINTF("(%s:%d) sent %d, remaining %d", IO_Handle->ip, IO_Handle->fd, num_sent, IO_Handle->tx_index);

        if (IO_Handle->tx_index)
        {
          memmove (IO_Handle->tx_buf, IO_Handle->tx_buf + num_sent, IO_Handle->tx_index);
          DEBUG_PRINTF("(%s:%d) sent %d, remaining %d", IO_Handle->ip, IO_Handle->fd, num_sent, IO_Handle->tx_index);
        }
        else
        {
          free (IO_Handle->tx_buf);
          IO_Handle->tx_buf = NULL;
        }
      }
      else
      {
        if (num_sent < 0)
        {
          if (errno != EAGAIN && errno != ENOSPC && errno != EWOULDBLOCK)
          {
            DEBUG_PRINTF("(%s:%d) send error: %s", IO_Handle->ip, IO_Handle->fd, strerror(errno));
            list_remove (&io_list, IO_Handle, io_cleanup, NULL);
            return;
          }
        }
      }

        //conn->CDR.out_bytes += num_sent;
        //conn->CDR.out_packets_estimate++;
    }
  }
}

//**********************************************************************************
void io_buffer_out (IO_Handle_t *IO_Handle, uint8_t *reply, int len)
{
  if (IO_Handle && reply && len > 0)
  {
    //DEBUG_PRINTF("(%s:%d) conn_add unencrypted %d", IO_Handle->ip, IO_Handle->fd, len);

    if (IO_Handle->ssl)
    {
      if (SSL_is_init_finished(IO_Handle->ssl))
      {
        /* Process outbound unencrypted data that are waiting to be encrypted.  The
         * waiting data resides in encrypt_buf.  It needs to be passed into the SSL
         * object for encryption, which in turn generates the encrypted bytes that then
         * will be queued for later socket write. */

        while (len > 0)
        {
          int n = SSL_write (IO_Handle->ssl, reply, len);

          if (n > 0)
          {
            /* consume the waiting bytes that have been used by SSL */

            reply += n;
            len -= n;

            /* take the output of the SSL object and queue it for socket write */
            bio_read (IO_Handle);
          }
          else
          {
            enum sslstatus status = get_sslstatus (IO_Handle->ssl, n);

            if (status == SSLSTATUS_FAIL)
            {
              io_shutdown (IO_Handle);
              return;
            }
          }
        }
      }
      else
        DEBUG_PRINTF("(%s:%d) ERROR: ssl not ready to send", IO_Handle->ip, IO_Handle->fd);
    }
    else
      io_add_raw (IO_Handle, reply, len);
  }
}

//**********************************************************************************
void release_io (IO_Handle_t *IO_Handle)
{
  if (IO_Handle)
  {
    //DEBUG_PRINTF("(%s:%d) release io", IO_Handle->ip, IO_Handle->fd);

    if (IO_Handle->io_cleanup)
    {
      IO_Handle->io_cleanup (IO_Handle);
      //IO_Handle->io_cleanup = NULL;
    }
    else
    {
      DEBUG_PRINTF("(%s:%d) no io cleanup", IO_Handle->ip, IO_Handle->fd);
    }

    //DEBUG_PRINTF( "==============================================================");
  }
}

//**********************************************************************************
IO_Handle_t *find_io (void *conn_ref)
{
  IO_Handle_t *IO_Handle = list_find (io_list, conn_ref);

  return IO_Handle;
}

//**********************************************************************************
static void buf_rx (IO_Handle_t *IO_Handle, uint8_t *buf, int len)
{
  IO_Handle->rx_buf = realloc (IO_Handle->rx_buf, IO_Handle->rx_index + len + 1); // destroys http_info pointers so have to rescan headers

  if (IO_Handle->rx_buf)
  {
    memcpy (IO_Handle->rx_buf + IO_Handle->rx_index, buf, len);

    IO_Handle->rx_index += len;
    IO_Handle->rx_buf [IO_Handle->rx_index] = '\0';

    //DEBUG_PRINTF("(%s:%d) %s adding %d new len %d", IO_Handle->ip, IO_Handle->fd, __func__, len, IO_Handle->rx_index);

    while (1)
    {
      if (IO_Handle->rx_index < 0)
      {
        DEBUG_PRINTF("(%s:%d) %d to process - HOW DOES THIS HAPPEN???????????", IO_Handle->ip, IO_Handle->fd, IO_Handle->rx_index);
        break; // from while
      }

      if (IO_Handle->rx_index == 0)
      {
        break; // from while
      }

      int length = 0;

      if (IO_Handle->io)
      {
        length = IO_Handle->io (IO_Handle);
      }
      else
      {
        DEBUG_PRINTF ("(%s:%d) no io handle", IO_Handle->ip, IO_Handle->fd);
        close (IO_Handle->fd); // force a read error
        break;
      }
      // conn could have died while sending

      if (length > 0)
      {
        //DEBUG_PRINTF("(%s:%d) parser returned %d of %d in buf", IO_Handle->ip, IO_Handle->fd, length, IO_Handle->rx_index);

        Timer_Add (IO_Handle->idle_time, SingleShot, io_timeout, IO_Handle);

        IO_Handle->rx_index -= length;

        if (IO_Handle->rx_index > 0)
        {
          memmove (IO_Handle->rx_buf, IO_Handle->rx_buf + length, IO_Handle->rx_index);
          DEBUG_PRINTF("(%s:%d) parsed out %d, remaining %d", IO_Handle->ip, IO_Handle->fd, length, IO_Handle->rx_index);
        }
        else
        {
          free (IO_Handle->rx_buf);
          IO_Handle->rx_buf = NULL;
          //DEBUG_PRINTF("(%s:%d) parsed all", IO_Handle->ip, IO_Handle->fd);
        }
      }
      else
      if (length < 0) // error or force a close
      {
        close (IO_Handle->fd); // force a read error
        break;
      }
      else
      {
        DEBUG_PRINTF("(%s:%d) incomplete %d of %d in buf", IO_Handle->ip, IO_Handle->fd, length, IO_Handle->rx_index);
        break; // from while 1
      }
    }
  }
}


//**********************************************************************************
void ssl_init (IO_Handle_t *IO_Handle)
{
  enum sslstatus status;
  int n;

  if (SSL_in_connect_init(IO_Handle->ssl))
      n = SSL_connect (IO_Handle->ssl);

  if (SSL_in_accept_init(IO_Handle->ssl))
      n = SSL_accept (IO_Handle->ssl);

  if (n != 1)
  {
    status = get_sslstatus (IO_Handle->ssl, n);

    /* Did SSL request to write bytes? */
    if (status == SSLSTATUS_WANT_IO)
      bio_read (IO_Handle);
  }
  else
  {
    check_cert (IO_Handle);

    if (IO_Handle->io)
      IO_Handle->io (IO_Handle);
  }
}


//**********************************************************************************
void ssl_decrypt (IO_Handle_t *IO_Handle, uint8_t *src, size_t len)
{
  enum sslstatus status;
  int n;

  while (len > 0)
  {
    n = BIO_write (IO_Handle->rbio, src, len);

    if (n <= 0)
    {
      DEBUG_PRINTF ("BIO WRITE ERROR %d: %s", n, ERR_reason_error_string (ERR_get_error()));
      return; /* if BIO write fails, assume unrecoverable */
    }

    src += n;
    len -= n;

    if (!SSL_is_init_finished (IO_Handle->ssl))
      ssl_init (IO_Handle);

    /* The encrypted data is now in the input bio so now we can perform actual
     * read of unencrypted data. */

    do
    {
      uint8_t buf[16 * 1024]; /* used for copying bytes out of SSL/BIO */

      n = SSL_read(IO_Handle->ssl, buf, sizeof(buf));

      if (n > 0)
        buf_rx (IO_Handle, buf, (size_t) n);

    } while (n > 0);

    status = get_sslstatus(IO_Handle->ssl, n);

    /* Did SSL request to write bytes? This can happen if peer has requested SSL
     * renegotiation. */

    if (status == SSLSTATUS_WANT_IO)
      bio_read (IO_Handle);
  }
}


//**********************************************************************************
static void io_rx (IO_Handle_t *IO_Handle)
{
  while (1)
  {
    uint8_t buf [16 * 1024];

    int len = read (IO_Handle->fd, buf, sizeof (buf));

    if (len == -1)
    { // If errno == EAGAIN, that means we have read all data. So go back to the main loop. */
      if (errno != EAGAIN && errno != EWOULDBLOCK)
      {
        DEBUG_PRINTF("(%s:%d) %s read error: %s", IO_Handle->ip, IO_Handle->fd, __func__, strerror(errno));
        list_remove(&io_list, IO_Handle, io_cleanup, NULL);
      }
      else
      {
        if (!IO_Handle->ssl)
          if (IO_Handle->io)
            IO_Handle->io (IO_Handle);
      }

      break; // from while
    }
    else
    if (len > 0)
    {
      //DEBUG_PRINTF("(%s:%d) received %d, remaining %d", IO_Handle->ip, IO_Handle->fd, len, IO_Handle->tx_index );

      if (IO_Handle->ssl)
        ssl_decrypt (IO_Handle, buf, len);
      else
        buf_rx (IO_Handle, buf, len);
    }
    else
    {
      break; // from while
    }
  }
}

//**********************************************************************************
void *io_connect (const char *ip, int port, int use_ssl, int idle_time, int size)
{
  IO_Handle_t *IO_Handle = NULL;

  if (isValidIpAddress (ip))
  {
    IO_Handle = list_add (&io_list, sizeof(IO_Handle_t) + size, "conn out");

    if (IO_Handle)
    {
      IO_Handle->fd = socket (AF_INET, SOCK_STREAM, 0);

      if (IO_Handle->fd < 0)
      {
        //perror ( "connection (client)" );
        DEBUG_PRINTF ("ERROR: opening (%s:%d) connection - %s", ip, port, strerror (errno));
        return NULL;
      }
      else
      {
        struct sockaddr_in connection_addr;

        // Set async/non block.
        fcntl (IO_Handle->fd, F_SETFL, O_NONBLOCK | fcntl (IO_Handle->fd, F_GETFL));
        bzero ((char *) &connection_addr, sizeof(connection_addr));
        connection_addr.sin_family      = AF_INET;
        connection_addr.sin_addr.s_addr = inet_addr (ip);
        connection_addr.sin_port        = htons (port);

        int res = connect (IO_Handle->fd, (struct sockaddr *) &connection_addr, sizeof (connection_addr));

        if (res < 0 && (errno != EINPROGRESS))
        {
          DEBUG_PRINTF ("New connection Error connecting to (%s:%d|%d) - %s", ip, port, IO_Handle->fd, strerror (errno));
          return NULL;
        }
        else
        {
          if (use_ssl)
          {
            extern SSL_CTX *client_ctx;

            if (client_ctx)
            {
              /* ----------------------------------------------- */
              /* TCP connection is ready. Do server side SSL. */

              IO_Handle->rbio = BIO_new (BIO_s_mem ());
              IO_Handle->wbio = BIO_new (BIO_s_mem ());

              IO_Handle->ssl = SSL_new (client_ctx);

              if (IO_Handle->ssl)
              {
                SSL_set_quiet_shutdown (IO_Handle->ssl, 1);

                SSL_set_connect_state (IO_Handle->ssl); /* sets ssl to work in client mode. */

                SSL_set_bio (IO_Handle->ssl, IO_Handle->rbio, IO_Handle->wbio);
              }
            }
          }

          if (idle_time)
            IO_Handle->idle_time = idle_time;
          else
            IO_Handle->idle_time = 60 * 2;

          IO_Handle->ip = strdup(ip);

          epoll_add (IO_Handle->fd, IO_Handle);
        }
      }
    }
    else
    {
      DEBUG_PRINTF("ERROR: No io handle created!");
      exit(EXIT_FAILURE);
    }
  }
  else
  {
    DEBUG_PRINTF ("%s is an not an IP", ip);
  }

  return IO_Handle;
}

//**********************************************************************************
void io_in (struct epoll_event *event)
{
  if (!Accept (event->data.ptr))
    {
      // We have data on the fd waiting to be read.
      // We must read whatever data is available completely,
      // as we are running in edge-triggered mode
      // and won't get a notification again for the same
      // data.

      IO_Handle_t *IO_Handle = list_find (io_list, event->data.ptr);

      if (IO_Handle)
      {
        if (IO_Handle->ssl)
          if (!SSL_is_init_finished (IO_Handle->ssl))
            ssl_init (IO_Handle);

        io_rx (IO_Handle); // check if we have something on the socket in queue

        Timer_Add (IO_Handle->idle_time, SingleShot, io_timeout, IO_Handle); // set or extend

        io_send (IO_Handle); // can destroy the handle;
      }
      else
      {
        DEBUG_PRINTF ("io in on unknown handle @ %zd", (size_t)event->data.ptr);
      }
    }

  io_poll (__func__);
}


//**********************************************************************************
void io_out ( struct epoll_event *event )
{
  io_in (event);
  io_poll (__func__);
}

//else // nothing to send - why are we here? maybe we just connected
//{
//  if (!IO_Handle->ssl)
//  {
//    if (IO_Handle->io)
//      IO_Handle->io (IO_Handle);
//  }
//}


//**********************************************************************************
void io_err (struct epoll_event *event)
{
  {
    IO_Handle_t *IO_Handle = list_find (io_list, event->data.ptr);

    if (IO_Handle)
    {
      io_close (IO_Handle);
    }
    else
    {
      DEBUG_PRINTF ("io err %zd", (size_t)event->data.ptr);
    }
  }

  io_poll (__func__);
}

//**********************************************************************************
void epoll_add (int fd, void *ptr)
{
  if (ptr && fd)
  {
    if (epoll_fd <= 0)
    {
      if ((epoll_fd = epoll_create1(0)) < 0)
      {
        DEBUG_PRINTF("%s epoll_create: %s", __func__, strerror(errno))
        abort();
      }
    }

    struct epoll_event event;

    event.data.ptr = ptr;

    event.events =  EPOLLIN | EPOLLET | EPOLLOUT;  // edge triggered notify of data in and out

    //DEBUG_PRINTF("epoll add fd %d",fd)

    if (epoll_ctl (epoll_fd, EPOLL_CTL_ADD, fd, &event) == -1) // add fd to the list of fds to monitor. */
    {
      //perror("epoll_ctl_add");
      DEBUG_PRINTF( "%s epoll_ctl_add: %s", __func__, strerror(errno) );
    }
  }
}

//**********************************************************************************
void epoll_remove (int fd)
{
  //DEBUG_PRINTF("epoll remove fd %d",fd)

  if (epoll_fd > 0)
  {
    if ( epoll_ctl ( epoll_fd, EPOLL_CTL_DEL, fd, NULL ) == -1 ) // add db socket fd to the list of fds to monitor. */
    {
      //perror("epoll_ctl_rem");
      DEBUG_PRINTF( "%s %d epoll_ctl_rem: %s", __func__, fd, strerror(errno) );
    }
  }
}

//**********************************************************************************
int approximate_max_events(void)
{
  FILE *file;

  int connections = 0;

  //DEBUG_PRINTF("reading /proc/meminfo");

  file = fopen("/proc/meminfo", "r");

  if (file)
  {
    char buf[128];
    int memsize = 0;

    while (fgets(buf, sizeof(buf), file))
    {
      //DEBUG_PRINTF("%s",buf)

      if (strncmp(buf, "MemTotal:", 9) == 0)
      {
        memsize = atoi(&buf[9]) / 1000000; // 1G
        //DEBUG_PRINTF("mem size set to %dG", memsize);
        break; // from while
      }
    }

    if (memsize) connections = memsize * 10000; // 10K units per 1G mem
    else
    {
      //DEBUG_PRINTF("Could not find MemTotal:");
    }

    fclose(file);
  }
  else
  {
    //DEBUG_PRINTF("Could not read /proc/meminfo");
  }

  if (connections < 10000) connections = 10000;

  //DEBUG_PRINTF("Max Conns = %d", connections);

  return connections;
}

//**********************************************************************************
void io_poll (const char *caller)
{
  list_t *list_walker = io_list;

  while (list_walker)
  {
    IO_Handle_t *IO_Handle = list_walk (&list_walker);

    if (IO_Handle->tx_index)
    {
      //DEBUG_PRINTF ("(%s:%d) POLL SENDING %d from %s", IO_Handle->ip, IO_Handle->fd, IO_Handle->tx_index, caller);
      io_send (IO_Handle);
    }
//
//    if (conn->IO_Handle->rx_index)
//    {
//      DEBUG_PRINTF ("POLL PARSING")
//      parse_rx_buf (conn);
//    }
  }
}


//**********************************************************************************
void check_events (void)
{
  int num_events, i;

  if (epoll_fd > 0)
  {
    if (max_events == 0)
      max_events = approximate_max_events();

    if (!events)
    {
      events = calloc(sizeof(struct epoll_event), max_events); // fd list for all fds needing attention

      if (!events)
      {
        DEBUG_PRINTF("Panic - Could not allocate mem for %d epoll events (%zd)", max_events, (sizeof(struct epoll_event) * max_events));
        exit(EXIT_FAILURE);
      }
    }

    num_events = epoll_wait (epoll_fd, events, max_events, 3000); // no longer than 100 ms to poll timer

    if (num_events > 0)
    {
      for (i = 0; i < num_events; i++)
      {
//        if (events[i].events)
//        {
//          DEBUG_PRINTF("EVENT %d %08X %s%s%s%s%s%s%s%s%s%s%s%s%s%s", i
//              , events[i].events
//              , events[i].events & EPOLLIN ? "EPOLLIN " : ""
//              , events[i].events & EPOLLPRI ? "EPOLLPRI " : ""
//              , events[i].events & EPOLLOUT ? "EPOLLOUT " : ""
//              , events[i].events & EPOLLRDNORM ? "EPOLLRDNORM " : ""
//              , events[i].events & EPOLLRDBAND ? "EPOLLRDBAND " : ""
//              , events[i].events & EPOLLWRNORM ? "EPOLLWRNORM " : ""
//              , events[i].events & EPOLLWRBAND ? "EPOLLWRBAND " : ""
//              , events[i].events & EPOLLMSG ? "EPOLLMSG " : ""
//              , events[i].events & EPOLLERR ? "EPOLLERR " : ""
//              , events[i].events & EPOLLHUP ? "EPOLLHUP " : ""
//              , events[i].events & EPOLLRDHUP ? "EPOLLRDHUP " : ""
//              , events[i].events & EPOLLWAKEUP ? "EPOLLWAKEUP " : ""
//              , events[i].events & EPOLLONESHOT ? "EPOLLONESHOT " : ""
//              , events[i].events & EPOLLET ? "EPOLLET " : "" );
//        }

        if (events[i].events & EPOLLIN)
        {
          io_in (&events[i]);
          events[i].events &= ~EPOLLIN;
        }

        if (events[i].events & EPOLLOUT)
        {
          io_out (&events[i]);
          events[i].events &= ~EPOLLOUT;
        }

        if (events[i].events)
        {
          io_err    (&events[i]);
        }
      }
    }
    else
    if (errno != 4)
    {
      DEBUG_PRINTF("epoll error %d, %s", errno, strerror(errno));
    }
  }
}

//EPOLLIN = 0x001,
//#define EPOLLIN EPOLLIN
//EPOLLPRI = 0x002,
//#define EPOLLPRI EPOLLPRI
//EPOLLOUT = 0x004,
//#define EPOLLOUT EPOLLOUT
//EPOLLRDNORM = 0x040,
//#define EPOLLRDNORM EPOLLRDNORM
//EPOLLRDBAND = 0x080,
//#define EPOLLRDBAND EPOLLRDBAND
//EPOLLWRNORM = 0x100,
//#define EPOLLWRNORM EPOLLWRNORM
//EPOLLWRBAND = 0x200,
//#define EPOLLWRBAND EPOLLWRBAND
//EPOLLMSG = 0x400,
//#define EPOLLMSG EPOLLMSG
//EPOLLERR = 0x008,
//#define EPOLLERR EPOLLERR
//EPOLLHUP = 0x010,
//#define EPOLLHUP EPOLLHUP
//EPOLLRDHUP = 0x2000,
//#define EPOLLRDHUP EPOLLRDHUP
//EPOLLONESHOT = 1u << 30,
//#define EPOLLONESHOT EPOLLONESHOT
//EPOLLET = 1u << 31
//#define EPOLLET EPOLLET



//long bio_dump_callback(BIO *bio, int cmd, const char *argp,
//                       int argi, long argl, long ret)
//{
//    if (cmd == (BIO_CB_READ | BIO_CB_RETURN))
//    {
//        printf("read from (%lu bytes => %ld (0x%lX))\n",
//                   (unsigned long)argi, ret, ret);
//        return (ret);
//    }
//    else if (cmd == (BIO_CB_WRITE | BIO_CB_RETURN))
//    {
//        printf("write to  (%lu bytes => %ld (0x%lX))\n",
//                   (unsigned long)argi, ret, ret);
//    }
//
//    return (ret);
//}

//int gen_session_id_callback (const SSL *ssl, unsigned char *id,
//                               unsigned int *id_len)
//{
//  *id = (int)GetUcTimeStamp();
//  *id_len = sizeof(int);
//
//  DEBUG_PRINTF("Session id %d generated", *id);
//
//  return 1;
//}
//
//
//static char *
//get_timestamp()
//{
//  static char timestamp[BUFSIZ];
//  struct timeval tv;
//  struct tm *t;
//
//  gettimeofday(&tv, NULL);
//  t = localtime(&tv.tv_sec);
//  sprintf(timestamp, "%04d/%02d/%02d %02d:%02d:%02d.%06d",
//    t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
//    t->tm_hour, t->tm_min, t->tm_sec, (int)tv.tv_usec);
//
//  return timestamp;
//}
//
//
//static void
//tlsext_cb(SSL * s, int client_server, int type,
//    unsigned char *data, int len, void *arg)
//{
////  BIO *bio = arg;
//  char *extname;
//
//  switch (type) {
//  case TLSEXT_TYPE_server_name:
//    extname = "server name";
//    break;
//  case TLSEXT_TYPE_max_fragment_length:
//    extname = "max fragment length";
//    break;
//  case TLSEXT_TYPE_client_certificate_url:
//    extname = "client certificate URL";
//    break;
//  case TLSEXT_TYPE_trusted_ca_keys:
//    extname = "trusted CA keys";
//    break;
//  case TLSEXT_TYPE_truncated_hmac:
//    extname = "truncated HMAC";
//    break;
//  case TLSEXT_TYPE_status_request:
//    extname = "status request";
//    break;
//  case TLSEXT_TYPE_user_mapping:
//    extname = "user mapping";
//    break;
//  case TLSEXT_TYPE_client_authz:
//    extname = "client authz";
//    break;
//  case TLSEXT_TYPE_server_authz:
//    extname = "server authz";
//    break;
//  case TLSEXT_TYPE_cert_type:
//    extname = "cert type";
//    break;
//  case TLSEXT_TYPE_elliptic_curves:
//    extname = "elliptic curves";
//    break;
//  case TLSEXT_TYPE_ec_point_formats:
//    extname = "EC point formats";
//    break;
//  case TLSEXT_TYPE_srp:
//    extname = "SRP";
//    break;
//  case TLSEXT_TYPE_signature_algorithms:
//    extname = "signature algorithms";
//    break;
//  case TLSEXT_TYPE_use_srtp:
//    extname = "use SRTP";
//    break;
//  case TLSEXT_TYPE_heartbeat:
//    extname = "heartbeat";
//    break;
//  case TLSEXT_TYPE_application_layer_protocol_negotiation:
//    extname = "ALPN";
//    break;
//  case TLSEXT_TYPE_padding:
//    extname = "padding";
//    break;
//  case TLSEXT_TYPE_session_ticket:
//    extname = "session ticket";
//    break;
//  case TLSEXT_TYPE_renegotiate:
//    extname = "renegotiation info";
//    break;
//
//#ifdef TLSEXT_TYPE_next_proto_neg
//  case TLSEXT_TYPE_next_proto_neg:
//    extname = "next protocol";
//    break;
//#endif
//
//  default:
//    extname = "unknown";
//    break;
//  }
//
//  printf("%s (tlsext) %s \"%s\" (id=%d) len=%d\n",
//      get_timestamp(), client_server ? "server" : "client",
//      extname, type, len);
//}
//


//
//https://www.openssl.org/docs/man1.1.0/ssl/SSL_get_error.html
//
//
//
//
//SSL_get_error
//NAME
//SSL_get_error - obtain result code for TLS/SSL I/O operation
//
//SYNOPSIS
// #include <openssl/ssl.h>
//
// int SSL_get_error(const SSL *ssl, int ret);
//DESCRIPTION
//SSL_get_error() returns a result code (suitable for the C "switch" statement) for a preceding call to SSL_connect(), SSL_accept(), SSL_do_handshake(), SSL_read(), SSL_peek(), or SSL_write() on ssl. The value returned by that TLS/SSL I/O function must be passed to SSL_get_error() in parameter ret.
//
//In addition to ssl and ret, SSL_get_error() inspects the current thread's OpenSSL error queue. Thus, SSL_get_error() must be used in the same thread that performed the TLS/SSL I/O operation, and no other OpenSSL function calls should appear in between. The current thread's error queue must be empty before the TLS/SSL I/O operation is attempted, or SSL_get_error() will not work reliably.
//
//RETURN VALUES
//The following return values can currently occur:
//
//SSL_ERROR_NONE
//The TLS/SSL I/O operation completed. This result code is returned if and only if ret > 0.
//
//SSL_ERROR_ZERO_RETURN
//The TLS/SSL connection has been closed. If the protocol version is SSL 3.0 or higher, this result code is returned only if a closure alert has occurred in the protocol, i.e. if the connection has been closed cleanly. Note that in this case SSL_ERROR_ZERO_RETURN does not necessarily indicate that the underlying transport has been closed.
//
//SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE
//The operation did not complete; the same TLS/SSL I/O function should be called again later. If, by then, the underlying BIO has data available for reading (if the result code is SSL_ERROR_WANT_READ) or allows writing data (SSL_ERROR_WANT_WRITE), then some TLS/SSL protocol progress will take place, i.e. at least part of an TLS/SSL record will be read or written. Note that the retry may again lead to a SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE condition. There is no fixed upper limit for the number of iterations that may be necessary until progress becomes visible at application protocol level.
//
//For socket BIOs (e.g. when SSL_set_fd() was used), select() or poll() on the underlying socket can be used to find out when the TLS/SSL I/O function should be retried.
//
//Caveat: Any TLS/SSL I/O function can lead to either of SSL_ERROR_WANT_READ and SSL_ERROR_WANT_WRITE. In particular, SSL_read() or SSL_peek() may want to write data and SSL_write() may want to read data. This is mainly because TLS/SSL handshakes may occur at any time during the protocol (initiated by either the client or the server); SSL_read(), SSL_peek(), and SSL_write() will handle any pending handshakes.
//
//SSL_ERROR_WANT_CONNECT, SSL_ERROR_WANT_ACCEPT
//The operation did not complete; the same TLS/SSL I/O function should be called again later. The underlying BIO was not connected yet to the peer and the call would block in connect()/accept(). The SSL function should be called again when the connection is established. These messages can only appear with a BIO_s_connect() or BIO_s_accept() BIO, respectively. In order to find out, when the connection has been successfully established, on many platforms select() or poll() for writing on the socket file descriptor can be used.
//
//SSL_ERROR_WANT_X509_LOOKUP
//The operation did not complete because an application callback set by SSL_CTX_set_client_cert_cb() has asked to be called again. The TLS/SSL I/O function should be called again later. Details depend on the application.
//
//SSL_ERROR_WANT_ASYNC
//The operation did not complete because an asynchronous engine is still processing data. This will only occur if the mode has been set to SSL_MODE_ASYNC using SSL_CTX_set_mode or SSL_set_mode and an asynchronous capable engine is being used. An application can determine whether the engine has completed its processing using select() or poll() on the asynchronous wait file descriptor. This file descriptor is available by calling SSL_get_all_async_fds or SSL_get_changed_async_fds. The TLS/SSL I/O function should be called again later. The function must be called from the same thread that the original call was made from.
//
//SSL_ERROR_WANT_ASYNC_JOB
//The asynchronous job could not be started because there were no async jobs available in the pool (see ASYNC_init_thread(3)). This will only occur if the mode has been set to SSL_MODE_ASYNC using SSL_CTX_set_mode or SSL_set_mode and a maximum limit has been set on the async job pool through a call to ASYNC_init_thread. The application should retry the operation after a currently executing asynchronous operation for the current thread has completed.
//
//SSL_ERROR_SYSCALL
//Some non-recoverable I/O error occurred. The OpenSSL error queue may contain more information on the error. For socket I/O on Unix systems, consult errno for details.
//
//SSL_ERROR_SSL
//A failure in the SSL library occurred, usually a protocol error. The OpenSSL error queue contains more information on the error.


//**********************************************************************************

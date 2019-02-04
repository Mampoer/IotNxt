/*
 * ssl.c
 *
 *  Created on: 25 Jan. 2018
 *      Author: root
 */

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "utils.h"

//time_t GetUcTimeStamp ( void );

char *pemfile   = NULL;
char *privfile  = NULL;
char *cafile    = NULL;
char *capath    = NULL;

char *global_cipher           = "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:CAMELLIA:DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA";

SSL_CTX *server_ctx = NULL;
SSL_CTX *client_ctx = NULL;

time_t GetUcTimeStamp ( void );

static int
dummy_ssl_verify_callback (int ok, X509_STORE_CTX *x509_store)
{
  return 1;
}

void init_openssl(char *hostname, char *appname, int unique)
{
  unsigned char c;

  int i;
  time_t uc_time;
  char *randbuf = NULL;
  size_t randbuf_size = 0;
  FILE *file;

  file = open_memstream (&randbuf, &randbuf_size);

  if ( file )
  {
    for ( i = 0; i < 4096; i++ )
    {
      uc_time = GetUcTimeStamp();
      fprintf(file, "%ld", uc_time);
    }

    fclose(file);

    RAND_seed(randbuf,strlen(randbuf));

    free(randbuf);
  }

//  if (RAND_poll() != 1)
//  {
//    perror("RAND_poll");
//    abort();
//  }

  if (RAND_bytes(&c, 1) != 1)
  {
    perror("RAND_bytes");
    abort();
  }

  SSL_library_init();

  SSL_load_error_strings();
  ERR_load_BIO_strings();
  ERR_load_crypto_strings();

  OpenSSL_add_all_algorithms();

//  server_ctx = SSL_CTX_new(SSLv23_server_method());
  server_ctx = SSL_CTX_new (TLSv1_2_server_method ());
//  server_ctx = SSL_CTX_new (TLS_server_method ());

  if (!server_ctx)
  {
    perror("Unable to create SSL context");
    ERR_print_errors_fp(stderr);
    abort();
  }

//  client_ctx = SSL_CTX_new (SSLv23_client_method ());
  client_ctx = SSL_CTX_new (TLSv1_2_client_method ());
//  client_ctx = SSL_CTX_new (TLS_client_method ());

  if (!client_ctx)
  {
    perror("Unable to create SSL context");
    ERR_print_errors_fp(stderr);
    abort();
  }

  SSL_CTX_set_options (server_ctx, SSL_OP_ALL
//      | SSL_OP_NO_COMPRESSION
      | SSL_OP_CIPHER_SERVER_PREFERENCE
      | SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION
      | SSL_OP_NO_SSLv2
      | SSL_OP_NO_SSLv3
      | SSL_OP_NO_TLSv1
      | SSL_OP_NO_TLSv1_1
      );

  SSL_CTX_set_mode (server_ctx,  SSL_MODE_RELEASE_BUFFERS
                        | SSL_MODE_AUTO_RETRY
                        | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER
                        | SSL_MODE_ENABLE_PARTIAL_WRITE       );

//  SSL_CTX_set_cert_flags (ctx, SSL_CERT_FLAG_TLS_STRICT);

  if (SSL_CTX_set_cipher_list(server_ctx, global_cipher) == 0)
  {
    perror("set_cipher_list");
    abort();
  }


  SSL_CTX_use_certificate_chain_file (server_ctx, pemfile);

  SSL_CTX_use_PrivateKey_file (server_ctx, privfile, SSL_FILETYPE_PEM);


//  char buf [SSL_MAX_SSL_SESSION_ID_LENGTH];
//
//  snprintf (buf, sizeof(buf), "%s%s%d", hostname, appname, unique);
//
//  buf [SSL_MAX_SSL_SESSION_ID_LENGTH - 1] = '\0';
//
//  SSL_CTX_set_session_id_context (ctx, (void *) &buf, strlen(buf));

  SSL_CTX_set_session_cache_mode (server_ctx, SSL_SESS_CACHE_OFF);
  //SSL_CTX_set_session_cache_mode (ctx, SSL_SESS_CACHE_SERVER);
  //SSL_CTX_set_session_cache_mode  (ctx, SSL_SESS_CACHE_SERVER);
  //SSL_CTX_sess_set_cache_size     (ctx, SSL_SESSION_CACHE_MAX_SIZE_DEFAULT);
}


//void handle_error(const char *file, int lineno, const char *msg) {
//  fprintf(stderr, "** %s:%i %s\n", file, lineno, msg);
//  ERR_print_errors_fp(stderr);
//  exit(1);
//}
//
//#define int_error(msg) handle_error(__FILE__, __LINE__, msg)
//
//void die(const char *msg) {
//  perror(msg);
//  exit(1);
//}
//
//
//void ssl_init()
//{
//  printf("initialising SSL\n");
//
//  /* SSL library initialisation */
//  SSL_library_init();
//  OpenSSL_add_all_algorithms();
//  SSL_load_error_strings();
//  ERR_load_BIO_strings();
//  ERR_load_crypto_strings();
//
//  /* create the SSL server context */
//  ctx = SSL_CTX_new(SSLv23_server_method());
//  if (!ctx)
//    die("SSL_CTX_new()");
//
//  /* Load certificate and private key files, and check consistency  */
//  int err;
//  err = SSL_CTX_use_certificate_file(ctx, pemfile,  SSL_FILETYPE_PEM);
//  if (err != 1)
//    int_error("SSL_CTX_use_certificate_file failed");
//  else
//    printf("certificate file loaded ok\n");
//
//  /* Indicate the key file to be used */
//  err = SSL_CTX_use_PrivateKey_file(ctx, privfile, SSL_FILETYPE_PEM);
//  if (err != 1)
//    int_error("SSL_CTX_use_PrivateKey_file failed");
//  else
//    printf("private-key file loaded ok\n");
//
//  /* Make sure the key and certificate file match. */
//  if (SSL_CTX_check_private_key(ctx) != 1)
//    int_error("SSL_CTX_check_private_key failed");
//  else
//    printf("private key verified ok\n");
//
//  /* Recommended to avoid SSLv2 & SSLv3 */
//  SSL_CTX_set_options(ctx, SSL_OP_ALL
////                          | SSL_MODE_RELEASE_BUFFERS
////                          | SSL_OP_NO_COMPRESSION
//                          | SSL_OP_NO_SSLv2
//                          | SSL_OP_NO_SSLv3
//                          | SSL_OP_NO_TLSv1
//                          | SSL_OP_NO_TLSv1_1 );
//}
//
//

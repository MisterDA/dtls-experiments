#if !defined(MBEDTLS_CONFIG_FILE)
#include <mbedtls/config.h>
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include <mbedtls/platform.h>
#else
#include <stdio.h>
#define mbedtls_printf     printf
#define mbedtls_fprintf    fprintf
#define mbedtls_time_t     time_t
#endif

#if !defined(MBEDTLS_SSL_SRV_C) || !defined(MBEDTLS_SSL_PROTO_DTLS) ||    \
    !defined(MBEDTLS_SSL_COOKIE_C) || !defined(MBEDTLS_NET_C) ||          \
    !defined(MBEDTLS_ENTROPY_C) || !defined(MBEDTLS_CTR_DRBG_C) ||        \
    !defined(MBEDTLS_X509_CRT_PARSE_C) || !defined(MBEDTLS_RSA_C) ||      \
    !defined(MBEDTLS_CERTS_C) || !defined(MBEDTLS_PEM_PARSE_C) ||         \
    !defined(MBEDTLS_TIMING_C)
#error "mbedTLS headers not available"
#else

#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <netinet/in.h>

#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/certs.h>
#include <mbedtls/x509.h>
#include <mbedtls/ssl.h>
#include <mbedtls/ssl_cookie.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/error.h>
#include <mbedtls/debug.h>
#include <mbedtls/timing.h>

#if defined(MBEDTLS_SSL_CACHE_C)
#include <mbedtls/ssl_cache.h>
#endif

#define min(x, y) ((x) <= (y) ? (x) : (y))

#define SERVER_PORT "5000"
#define SERVER_ADDR "::1"

#define READ_TIMEOUT_MS 10000
#define DEBUG_LEVEL 0

#define BUFLEN 4096

static void print_buf(const unsigned char *buf, size_t len) {
  static size_t n = 0;
  size_t i;
  printf("=== %zu ===\n", n++);
  for (i = 0; i < len; i++)
    printf("%x", buf[i]);
  if (i < len)
    printf("%02x", buf[i]);
  puts("\n\n");
}

struct neighbour {
  struct neighbour *next;

  struct sockaddr_in6 addr;
  mbedtls_ssl_context ssl;

  int fd;
  const unsigned char *buf;
  size_t len;
};

static int
net_recv(void *ctx, unsigned char *buf, size_t len)
{
  struct neighbour *n = ctx;
  int rc = min(len, n->len);
  memcpy(buf, n->buf, rc);
  printf("RECEIVED\n");
  print_buf(buf, rc);
  return rc;
}

static int
net_recv_timeout(void *ctx, unsigned char *buf, size_t len, uint32_t timeout)
{
  /* XXX block? */
  mbedtls_net_usleep(timeout * 1e3);
  return net_recv(ctx, buf, len);
}

static int
net_send(void *ctx, const unsigned char *buf, size_t len)
{
  struct neighbour *n = ctx;
  int rc;
  printf("SENDING %zu\n", len);
  print_buf(buf, len);
  rc = sendto(n->fd, buf, len, 0,
	      (const struct sockaddr *)&n->addr, sizeof(n->addr));
  return rc;
}


struct babel_dtls {
  mbedtls_ssl_cookie_ctx cookie_ctx;

  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;

  mbedtls_ssl_config conf;
  mbedtls_x509_crt srvcert;
  mbedtls_pk_context pkey;
  mbedtls_timing_delay_context timer;
#if defined(MBEDTLS_SSL_CACHE_C)
  mbedtls_ssl_cache_context cache;
#endif
};

static int
babel_dtls_init(struct babel_dtls *dtls)
{
  int ret;
  const char *pers = "dtls_server";

  mbedtls_ssl_config_init( &dtls->conf );
  mbedtls_ssl_cookie_init( &dtls->cookie_ctx );
#if defined(MBEDTLS_SSL_CACHE_C)
  mbedtls_ssl_cache_init( &dtls->cache );
#endif
  mbedtls_x509_crt_init( &dtls->srvcert );
  mbedtls_pk_init( &dtls->pkey );
  mbedtls_entropy_init( &dtls->entropy );
  mbedtls_ctr_drbg_init( &dtls->ctr_drbg );

#if defined(MBEDTLS_DEBUG_C)
  mbedtls_debug_set_threshold( DEBUG_LEVEL );
#endif

  printf( "\n  . Loading the server cert. and key..." );
  fflush( stdout );

  ret = mbedtls_x509_crt_parse( &dtls->srvcert, (const unsigned char *) mbedtls_test_srv_crt,
				mbedtls_test_srv_crt_len );
  if( ret != 0 )
    {
      printf( " failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret );
      goto exit;
    }

  ret = mbedtls_x509_crt_parse( &dtls->srvcert, (const unsigned char *) mbedtls_test_cas_pem,
				mbedtls_test_cas_pem_len );
  if( ret != 0 )
    {
      printf( " failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret );
      goto exit;
    }

  ret =  mbedtls_pk_parse_key( &dtls->pkey, (const unsigned char *) mbedtls_test_srv_key,
			       mbedtls_test_srv_key_len, NULL, 0 );
  if( ret != 0 )
    {
      printf( " failed\n  !  mbedtls_pk_parse_key returned %d\n\n", ret );
      goto exit;
    }

  printf( " ok\n" );

  printf( "  . Seeding the random number generator..." );
  fflush( stdout );

  if( ( ret = mbedtls_ctr_drbg_seed( &dtls->ctr_drbg, mbedtls_entropy_func, &dtls->entropy,
				     (const unsigned char *) pers,
				     strlen( pers ) ) ) != 0 )
    {
      printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
      goto exit;
    }

  printf( " ok\n" );

  printf( "  . Setting up the DTLS data..." );
  fflush( stdout );

  if( ( ret = mbedtls_ssl_config_defaults( &dtls->conf,
					   MBEDTLS_SSL_IS_SERVER,
					   MBEDTLS_SSL_TRANSPORT_DATAGRAM,
					   MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 )
    {
      mbedtls_printf( " failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret );
      goto exit;
    }

  mbedtls_ssl_conf_rng( &dtls->conf, mbedtls_ctr_drbg_random, &dtls->ctr_drbg );
  // mbedtls_ssl_conf_dbg( &dtls->conf, my_debug, stdout );

#if defined(MBEDTLS_SSL_CACHE_C)
  mbedtls_ssl_conf_session_cache( &dtls->conf, &dtls->cache,
				  mbedtls_ssl_cache_get,
				  mbedtls_ssl_cache_set );
#endif

  mbedtls_ssl_conf_ca_chain( &dtls->conf, dtls->srvcert.next, NULL );
  ret = mbedtls_ssl_conf_own_cert( &dtls->conf, &dtls->srvcert, &dtls->pkey );
  if (ret)
    {
      printf( " failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret );
      goto exit;
    }

  ret = mbedtls_ssl_cookie_setup( &dtls->cookie_ctx,
				  mbedtls_ctr_drbg_random, &dtls->ctr_drbg );
  if (ret)
    {
      printf( " failed\n  ! mbedtls_ssl_cookie_setup returned %d\n\n", ret );
      goto exit;
    }

  mbedtls_ssl_conf_dtls_cookies( &dtls->conf, mbedtls_ssl_cookie_write, mbedtls_ssl_cookie_check,
				 &dtls->cookie_ctx );

  return 0;
 exit:
  return 1;
}

static void
babel_dtls_free(struct babel_dtls *dtls)
{
  mbedtls_x509_crt_free( &dtls->srvcert );
  mbedtls_pk_free( &dtls->pkey );

  mbedtls_ssl_config_free( &dtls->conf );
  mbedtls_ssl_cookie_free( &dtls->cookie_ctx );
#if defined(MBEDTLS_SSL_CACHE_C)
  mbedtls_ssl_cache_free( &dtls->cache );
#endif
  mbedtls_ctr_drbg_free( &dtls->ctr_drbg );
  mbedtls_entropy_free( &dtls->entropy );
}

static int
neighbour_init(struct neighbour *neigh, struct babel_dtls *dtls,
	       struct sockaddr_in6 *addr, int fd)
{
  int ret;

  mbedtls_ssl_init( &neigh->ssl );

  if( ( ret = mbedtls_ssl_setup( &neigh->ssl, &dtls->conf ) ) != 0 )
    {
      printf( " failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret );
      goto exit;
    }

  mbedtls_ssl_set_timer_cb( &neigh->ssl, &dtls->timer, mbedtls_timing_set_delay,
			    mbedtls_timing_get_delay );

  memcpy(&neigh->addr, addr, sizeof(*addr));
  neigh->fd = fd;

  return 0;
 exit:
  return 1;
}

static struct neighbour *
list_get(struct neighbour *n, struct sockaddr_in6 *addr)
{
  while (n) {
    if (memcmp(&n->addr, addr, sizeof(*addr)) == 0)
      return n;
    n = n->next;
  }
  return NULL;
}

int main( void )
{
    int ret, len;

    unsigned char buf[BUFLEN];
    unsigned char client_ip[16] = { 0 };
    size_t cliip_len;

    mbedtls_net_context listen_fd;

    struct babel_dtls dtls;
    babel_dtls_init(&dtls);

    struct neighbour *neighbours = NULL;

    mbedtls_net_init( &listen_fd );

    printf( "  . Bind on udp/*/5000 ..." );
    fflush( stdout );

    if( ( ret = mbedtls_net_bind( &listen_fd, SERVER_ADDR, SERVER_PORT, MBEDTLS_NET_PROTO_UDP ) ) != 0 )
      {
	printf( " failed\n  ! mbedtls_net_bind returned %d\n\n", ret );
	goto exit;
      }

    printf( " ok\n" );


    ret = mbedtls_net_set_nonblock(&listen_fd);
    if (ret)
      {
        printf(" failed\n  ! mbedtls_net_set_nonblock %d\n\n", ret);
        goto exit;
      }

#if 1

reset:

    /* mbedtls_net_free( &neigh.client_fd ); */

    /* mbedtls_ssl_session_reset( &neigh.ssl ); */

    printf( "  . Waiting for a remote connection ...\n" );
    fflush( stdout );


    while (1) {
      /* UDP: wait for a message, but keep it in the queue */
      struct sockaddr_in6 client_addr;
      socklen_t n = sizeof(client_addr);

      /* ret = (int) recvfrom( listen_fd.fd, NULL, 0, MSG_PEEK, */
      /* 			    (struct sockaddr *) &client_addr, &n ); */

      /* waiting for a read */
      ret = 0;
      errno = 0;
      do {
	ret = (int) recvfrom( listen_fd.fd, buf, BUFLEN, 0,
			      (struct sockaddr *) &client_addr, &n );
      } while ( ret == -1 && (errno == EAGAIN || errno == EWOULDBLOCK));
      // print_buf(buf, ret);

      struct neighbour *neigh = list_get(neighbours, &client_addr);
      if (neigh) {
	printf("found neighbour\n");
	neigh->buf = buf;
	neigh->len = ret;
	if (neigh->ssl.state != MBEDTLS_SSL_HANDSHAKE_OVER) {
	  ret = mbedtls_ssl_handshake_step( &neigh->ssl );
	  if (ret) {
	    printf( " failed\n  ! "
		    "mbedtls_ssl_handshake_step() HERE returned -0x%x\n\n", -ret);
	  }
	} else if (ret == MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED) {
	  printf( " hello verification requested\n" );
	  ret = 0;
	  // reset
	  mbedtls_ssl_session_reset( &neigh->ssl );
	} else {
	  printf( "  < Read from client:" );
	}
      } else {
	printf("new neighbour\n");
        neigh = malloc(sizeof(*neigh));
	neighbour_init(neigh, &dtls, &client_addr, listen_fd.fd);
	neigh->buf = buf;
	neigh->len = ret;
	neigh->next = neighbours;
	neighbours = neigh;

	/* For HelloVerifyRequest cookies */
	if( ( ret = mbedtls_ssl_set_client_transport_id( &neigh->ssl,
							 client_addr.sin6_addr.s6_addr,
							 sizeof(client_addr.sin6_addr.s6_addr) ) ) != 0 )
	  {
	    printf( " failed\n  ! "
		    "mbedtls_ssl_set_client_transport_id() returned -0x%x\n\n", -ret );
	    goto exit;
	  }

	printf("ssl_set_bio\n");
	mbedtls_ssl_set_bio(&neigh->ssl, neigh,
			    net_send, net_recv, net_recv_timeout);

	ret = mbedtls_ssl_handshake_step( &neigh->ssl );
	printf("%d READ: %d WRITE: %d HVR: %d\n", ret,
	       MBEDTLS_ERR_SSL_WANT_READ,	
	       MBEDTLS_ERR_SSL_WANT_WRITE,
	       MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED);
	ret = mbedtls_ssl_handshake_step( &neigh->ssl );
	printf("%d READ: %d WRITE: %d HVR: %d\n", ret,
	       MBEDTLS_ERR_SSL_WANT_READ,	
	       MBEDTLS_ERR_SSL_WANT_WRITE,
	       MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED);
	if (ret == MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED) {
	  printf( " hello verification requested\n" );
	  mbedtls_ssl_session_reset( &neigh->ssl );
	} else if (ret) {
	  printf( " failed\n  ! "
		  "mbedtls_ssl_handshake_step() returned -0x%x\n\n", -ret);
	}
      }

#ifdef MBEDTLS_ERROR_C
      if( ret != 0 )
	{
	  char error_buf[100];
	  mbedtls_strerror( ret, error_buf, 100 );
	  printf("Last error was: %d - %s\n\n", ret, error_buf );
	}
#endif
    }

    #if 0

    printf( "  < Read from client:" );
    fflush( stdout );

    len = sizeof( buf ) - 1;
    memset( buf, 0, sizeof( buf ) );

    do ret = mbedtls_ssl_read( &neigh.ssl, buf, len );
    while( ret == MBEDTLS_ERR_SSL_WANT_READ ||
           ret == MBEDTLS_ERR_SSL_WANT_WRITE );

    if( ret <= 0 )
    {
        switch( ret )
        {
            case MBEDTLS_ERR_SSL_TIMEOUT:
                printf( " timeout\n\n" );
                goto reset;

            case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                printf( " connection was closed gracefully\n" );
                ret = 0;
                goto close_notify;

            default:
                printf( " mbedtls_ssl_read returned -0x%x\n\n", -ret );
                goto reset;
        }
    }

    len = ret;
    printf( " %d bytes read\n\n%s\n\n", len, buf );

    printf( "  > Write to client:" );
    fflush( stdout );

    do ret = mbedtls_ssl_write( &neigh.ssl, buf, len );
    while( ret == MBEDTLS_ERR_SSL_WANT_READ ||
           ret == MBEDTLS_ERR_SSL_WANT_WRITE );

    if( ret < 0 )
    {
        printf( " failed\n  ! mbedtls_ssl_write returned %d\n\n", ret );
        goto exit;
    }

    len = ret;
    printf( " %d bytes written\n\n%s\n\n", len, buf );

close_notify:
    printf( "  . Closing the connection..." );

    /* No error checking, the connection might be closed already */
    do ret = mbedtls_ssl_close_notify( &neigh.ssl );
    while( ret == MBEDTLS_ERR_SSL_WANT_WRITE );
    ret = 0;

    printf( " done\n" );

    goto reset;

#endif

exit:

#ifdef MBEDTLS_ERROR_C
    if( ret != 0 )
    {
        char error_buf[100];
        mbedtls_strerror( ret, error_buf, 100 );
        printf( "Last error was: %d - %s\n\n", ret, error_buf );
    }
#endif

    while (neighbours) {
      struct neighbour *n = neighbours->next;
      mbedtls_ssl_free( &n->ssl );
      free(neighbours);
      neighbours = n;
    }

    babel_dtls_free( &dtls );
    mbedtls_net_free( &listen_fd );

    return( ret < 0 ? 1 : 0 );
#endif
}
#endif /* MBEDTLS_SSL_SRV_C && MBEDTLS_SSL_PROTO_DTLS &&
          MBEDTLS_SSL_COOKIE_C && MBEDTLS_NET_C && MBEDTLS_ENTROPY_C &&
          MBEDTLS_CTR_DRBG_C && MBEDTLS_X509_CRT_PARSE_C && MBEDTLS_RSA_C
          && MBEDTLS_CERTS_C && MBEDTLS_PEM_PARSE_C && MBEDTLS_TIMING_C */

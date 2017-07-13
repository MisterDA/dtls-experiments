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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
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

#define SERVER_PORT "5000"
#define SERVER_ADDR "::1"

#define READ_TIMEOUT_MS 10000
#define DEBUG_LEVEL 0

static void my_debug( void *ctx, int level,
                      const char *file, int line,
                      const char *str )
{
    ((void) level);

    mbedtls_fprintf( (FILE *) ctx, "%s:%04d: %s", file, line, str );
    fflush(  (FILE *) ctx  );
}

static void print_buf(const unsigned char *buf, size_t len) {
  static size_t n = 0;
  size_t i;
  printf("\n=== %zu ===\n", n++);
  for (i = 0; i < len; i++)
    printf("%x", buf[i]);
  if (i < len)
    printf("%02x", buf[i]);
  putchar('\n');
}

static int
net_recv(void *ctx, unsigned char *buf, size_t len)
{
  int rv = mbedtls_net_recv(ctx, buf, len);
  print_buf(buf, rv);
  return rv;
}

static int
net_recv_timeout(void *ctx, unsigned char *buf, size_t len, uint32_t timeout)
{
  int rv = mbedtls_net_recv_timeout(ctx, buf, len, timeout);
  print_buf(buf, rv);
  return rv;
}

static int
net_send(void *ctx, const unsigned char *buf, size_t len)
{
  int rv = mbedtls_net_send(ctx, buf, len);
  print_buf(buf, rv);
  return rv;
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

static void
babel_dtls_init(struct babel_dtls *dtls)
{
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
}

static int
babel_dtls_setup(struct babel_dtls *dtls)
{
  int ret;
  const char *pers = "dtls_server";

  /*
   * 1. Load the certificates and private RSA key
   */
  printf( "\n  . Loading the server cert. and key..." );
  fflush( stdout );

  /*
   * This demonstration program uses embedded test certificates.
   * Instead, you may want to use mbedtls_x509_crt_parse_file() to read the
   * server and CA certificates, as well as mbedtls_pk_parse_keyfile().
   */
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


  /*
   * 3. Seed the RNG
   */
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

  /*
   * 4. Setup stuff
   */
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
  mbedtls_ssl_conf_dbg( &dtls->conf, my_debug, stdout );

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

struct neighbour {
  mbedtls_net_context client_fd;
  mbedtls_ssl_context ssl;
};

static void
neighbour_init(struct neighbour *neigh)
{
  mbedtls_net_init( &neigh->client_fd );
  mbedtls_ssl_init( &neigh->ssl );
}

static int
neighbour_setup(struct neighbour *neigh, struct babel_dtls *dtls)
{
  int ret;
  if( ( ret = mbedtls_ssl_setup( &neigh->ssl, &dtls->conf ) ) != 0 )
    {
      printf( " failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret );
      goto exit;
    }

  mbedtls_ssl_set_timer_cb( &neigh->ssl, &dtls->timer, mbedtls_timing_set_delay,
			    mbedtls_timing_get_delay );
  return 0;
 exit:
  return 1;
}

int main( void )
{
    int ret, len;

    unsigned char buf[1024];
    unsigned char client_ip[16] = { 0 };
    size_t cliip_len;


    mbedtls_net_context listen_fd;

    struct babel_dtls dtls;
    babel_dtls_init(&dtls);
    babel_dtls_setup(&dtls);

    struct neighbour neigh;
    neighbour_init(&neigh);
    neighbour_setup(&neigh, &dtls);

    mbedtls_net_init( &listen_fd );
    
    /*
    ret = mbedtls_net_set_nonblock(&dtls->listen_fd);
    if (ret)
      {
        printf(" failed\n  ! mbedtls_net_set_nonblock %d\n\n", ret);
        goto exit;
      }
    */ 
    printf( "  . Bind on udp/*/5000 ..." );
    fflush( stdout );

    if( ( ret = mbedtls_net_bind( &listen_fd, SERVER_ADDR, SERVER_PORT, MBEDTLS_NET_PROTO_UDP ) ) != 0 )
      {
	printf( " failed\n  ! mbedtls_net_bind returned %d\n\n", ret );
	goto exit;
      }

    printf( " ok\n" );


#if 1

reset:
#ifdef MBEDTLS_ERROR_C
    if( ret != 0 )
    {
        char error_buf[100];
        mbedtls_strerror( ret, error_buf, 100 );
        printf("Last error was: %d - %s\n\n", ret, error_buf );
    }
#endif

    mbedtls_net_free( &neigh.client_fd );

    mbedtls_ssl_session_reset( &neigh.ssl );

    /*
     * 3. Wait until a client connects
     */
    printf( "  . Waiting for a remote connection ..." );
    fflush( stdout );

    if( ( ret = mbedtls_net_accept( &listen_fd, &neigh.client_fd,
                    client_ip, sizeof( client_ip ), &cliip_len ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_net_accept returned %d\n\n", ret );
        goto exit;
    }

    /* For HelloVerifyRequest cookies */
    if( ( ret = mbedtls_ssl_set_client_transport_id( &neigh.ssl,
                    client_ip, cliip_len ) ) != 0 )
    {
        printf( " failed\n  ! "
                "mbedtls_ssl_set_client_transport_id() returned -0x%x\n\n", -ret );
        goto exit;
    }

    /* mbedtls_ssl_set_bio( &ssl, &client_fd, */
    /*                      mbedtls_net_send, mbedtls_net_recv, mbedtls_net_recv_timeout ); */

    mbedtls_ssl_set_bio(&neigh.ssl, &neigh.client_fd,
			net_send, net_recv, net_recv_timeout);

    printf( " ok\n" );

    /*
     * 5. Handshake
     */
    printf( "  . Performing the DTLS handshake..." );
    fflush( stdout );

    do ret = mbedtls_ssl_handshake( &neigh.ssl );
    while( ret == MBEDTLS_ERR_SSL_WANT_READ ||
           ret == MBEDTLS_ERR_SSL_WANT_WRITE );

    if( ret == MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED )
    {
        printf( " hello verification requested\n" );
        ret = 0;
        goto reset;
    }
    else if( ret != 0 )
    {
        printf( " failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", -ret );
        goto reset;
    }

    printf( " ok\n" );

    /*
     * 6. Read the echo Request
     */
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

    /*
     * 7. Write the 200 Response
     */
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

    /*
     * 8. Done, cleanly close the connection
     */
close_notify:
    printf( "  . Closing the connection..." );

    /* No error checking, the connection might be closed already */
    do ret = mbedtls_ssl_close_notify( &neigh.ssl );
    while( ret == MBEDTLS_ERR_SSL_WANT_WRITE );
    ret = 0;

    printf( " done\n" );

    goto reset;

    /*
     * Final clean-ups and exit
     */
exit:

#ifdef MBEDTLS_ERROR_C
    if( ret != 0 )
    {
        char error_buf[100];
        mbedtls_strerror( ret, error_buf, 100 );
        printf( "Last error was: %d - %s\n\n", ret, error_buf );
    }
#endif

    mbedtls_net_free( &neigh.client_fd );
    mbedtls_ssl_free( &neigh.ssl );

    babel_dtls_free( &dtls );
    mbedtls_net_free( &listen_fd );

    /* Shell can not handle large exit numbers -> 1 for errors */
    if( ret < 0 )
        ret = 1;

    return( ret );
#endif
}
#endif /* MBEDTLS_SSL_SRV_C && MBEDTLS_SSL_PROTO_DTLS &&
          MBEDTLS_SSL_COOKIE_C && MBEDTLS_NET_C && MBEDTLS_ENTROPY_C &&
          MBEDTLS_CTR_DRBG_C && MBEDTLS_X509_CRT_PARSE_C && MBEDTLS_RSA_C
          && MBEDTLS_CERTS_C && MBEDTLS_PEM_PARSE_C && MBEDTLS_TIMING_C */

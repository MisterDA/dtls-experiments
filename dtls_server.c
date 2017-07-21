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

#if !defined(MBEDTLS_SSL_SRV_C) || !defined(MBEDTLS_SSL_PROTO_DTLS) ||	\
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
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

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
#define SERVER_IP "::1"

#define READ_TIMEOUT_MS 10000
#define DEBUG_LEVEL 0

#define BUFLEN 4096

#ifdef MBEDTLS_ERROR_C
#define print_mbedtls_err(rc)					\
if(rc) {							\
  char error_buf[100];						\
  mbedtls_strerror(rc, error_buf, 100);				\
  printf("Last error was: -%#x - %s\n\n", rc, error_buf);	\
}
#else
#define print_mbedtls_err(rc)
#endif

static void
my_debug(void *ctx,int level,
	 const char *file, int line,
	 const char *str)
{
  ((void) level);

  mbedtls_fprintf((FILE *) ctx, "%s:%04d: %s", file, line, str);
  fflush((FILE *) ctx);
}


static void
print_buf(const unsigned char *buf, size_t len) {
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
  printf("RECEIVED %d\n", rc);
  print_buf(buf, rc);
  return rc;
}

static int
net_recv_timeout(void *ctx, unsigned char *buf, size_t len, uint32_t timeout)
{
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
  int rc;
  const unsigned char pers[] = "dtls_server";

  mbedtls_ssl_config_init(&dtls->conf);
  mbedtls_ssl_cookie_init(&dtls->cookie_ctx);
#if defined(MBEDTLS_SSL_CACHE_C)
  mbedtls_ssl_cache_init(&dtls->cache);
#endif
  mbedtls_x509_crt_init(&dtls->srvcert);
  mbedtls_pk_init(&dtls->pkey);
  mbedtls_entropy_init(&dtls->entropy);
  mbedtls_ctr_drbg_init(&dtls->ctr_drbg);

#if defined(MBEDTLS_DEBUG_C)
  mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif

  rc = mbedtls_x509_crt_parse(&dtls->srvcert,
			      (const unsigned char *) mbedtls_test_srv_crt,
			      mbedtls_test_srv_crt_len );
  if(rc) {
    printf("failed ! mbedtls_x509_crt_parse returned %d\n\n", rc);
    goto exit;
  }

  rc = mbedtls_x509_crt_parse(&dtls->srvcert,
			       (const unsigned char *) mbedtls_test_cas_pem,
			       mbedtls_test_cas_pem_len);
  if(rc) {
    printf("failed ! mbedtls_x509_crt_parse returned %d\n\n", rc);
    goto exit;
  }

  rc = mbedtls_pk_parse_key(&dtls->pkey,
			    (const unsigned char *) mbedtls_test_srv_key,
			    mbedtls_test_srv_key_len,
			    NULL, 0);
  if(rc) {
    printf("failed ! mbedtls_pk_parse_key returned %d\n\n", rc);
    goto exit;
  }

  rc = mbedtls_ctr_drbg_seed(&dtls->ctr_drbg, mbedtls_entropy_func, &dtls->entropy,
			     pers, sizeof(pers));
  if(rc) {
    printf("failed ! mbedtls_ctr_drbg_seed returned %d\n\n", rc);
    goto exit;
  }

  rc = mbedtls_ssl_config_defaults(&dtls->conf,
				   MBEDTLS_SSL_IS_SERVER,
				   MBEDTLS_SSL_TRANSPORT_DATAGRAM,
				   MBEDTLS_SSL_PRESET_DEFAULT);
  if(rc) {
    mbedtls_printf("failed ! mbedtls_ssl_config_defaults returned %d\n\n", rc);
    goto exit;
  }

  mbedtls_ssl_conf_rng(&dtls->conf, mbedtls_ctr_drbg_random, &dtls->ctr_drbg);

  mbedtls_ssl_conf_dbg(&dtls->conf, my_debug, stdout);

#if defined(MBEDTLS_SSL_CACHE_C)
  mbedtls_ssl_conf_session_cache(&dtls->conf, &dtls->cache,
				 mbedtls_ssl_cache_get,
				 mbedtls_ssl_cache_set);
#endif

  mbedtls_ssl_conf_ca_chain(&dtls->conf, dtls->srvcert.next, NULL);
  rc = mbedtls_ssl_conf_own_cert(&dtls->conf, &dtls->srvcert, &dtls->pkey);
  if(rc) {
    printf("failed ! mbedtls_ssl_conf_own_cert returned %d\n\n", rc);
    goto exit;
  }

  rc = mbedtls_ssl_cookie_setup(&dtls->cookie_ctx,
				mbedtls_ctr_drbg_random, &dtls->ctr_drbg);
  if(rc) {
    printf("failed ! mbedtls_ssl_cookie_setup returned %d\n\n", rc);
    goto exit;
  }

  mbedtls_ssl_conf_dtls_cookies(&dtls->conf, mbedtls_ssl_cookie_write,
				mbedtls_ssl_cookie_check,
				&dtls->cookie_ctx);

 exit:
  return rc;
}

static void
babel_dtls_free(struct babel_dtls *dtls)
{
  mbedtls_x509_crt_free(&dtls->srvcert);
  mbedtls_pk_free(&dtls->pkey);

  mbedtls_ssl_config_free(&dtls->conf );
  mbedtls_ssl_cookie_free(&dtls->cookie_ctx);
#if defined(MBEDTLS_SSL_CACHE_C)
  mbedtls_ssl_cache_free(&dtls->cache);
#endif
  mbedtls_ctr_drbg_free(&dtls->ctr_drbg);
  mbedtls_entropy_free(&dtls->entropy);
}

static int
neighbour_init(struct neighbour *neigh, struct babel_dtls *dtls,
	       struct sockaddr_in6 *addr, int fd)
{
  int rc;

  mbedtls_ssl_init(&neigh->ssl);

  rc = mbedtls_ssl_setup(&neigh->ssl, &dtls->conf);
  if(rc) {
    printf("failed ! mbedtls_ssl_setup returned %d\n\n", rc);
    goto exit;
  }

  mbedtls_ssl_set_timer_cb(&neigh->ssl, &dtls->timer,
			   mbedtls_timing_set_delay,
			   mbedtls_timing_get_delay);

  memcpy(&neigh->addr, addr, sizeof(*addr));
  neigh->fd = fd;

 exit:
  return rc;
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

static int
net_bind(int *fd)
{
  int n, rc;
  struct addrinfo hints, *addr_list, *cur;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET6;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_protocol = IPPROTO_UDP;
  hints.ai_flags = AI_PASSIVE;

  if(getaddrinfo(NULL, SERVER_PORT, &hints, &addr_list) != 0)
    return -1;

  rc = -1;
  for(cur = addr_list; cur != NULL; cur = cur->ai_next) {
    *fd = (int) socket( cur->ai_family, cur->ai_socktype,
			cur->ai_protocol );
    if(*fd < 0)
      continue;

    n = 1;
    if(setsockopt(*fd, SOL_SOCKET, SO_REUSEADDR,
		  (const char *) &n, sizeof(n)) != 0) {
      close(*fd);
      rc = -1;
      continue;
    }

    if(bind(*fd, cur->ai_addr, cur->ai_addrlen) != 0) {
      close(*fd);
      rc = -1;
      continue;
    }
    rc = 0;
    break;
  }

  freeaddrinfo(addr_list);

  return rc;
}


int main(void)
{
  struct neighbour *neighbours = NULL;
  struct babel_dtls dtls;
  int listen_fd;

  unsigned char buf[BUFLEN];
  int rc;

  rc = babel_dtls_init(&dtls);
  if(rc) {
    print_mbedtls_err(rc);
    return 1;
  }

  if (net_bind(&listen_fd) != 0) {
    printf("Could not bind socket\n");
    return 1;
  }

  printf("Waiting for a remote connection ...\n");
  fflush(stdout );

  while (1) {
    struct neighbour *neighbour;
    struct sockaddr_in6 client_addr;
    socklen_t n = sizeof(client_addr);

    rc = recvfrom(listen_fd, buf, BUFLEN, 0,
  		  (struct sockaddr *) &client_addr, &n);

    neighbour = list_get(neighbours, &client_addr);
    if (neighbour) {
      printf("Neighbour found.\n");
      neighbour->len = rc;
      rc = mbedtls_ssl_handshake(&neighbour->ssl);
      if(rc) {
	printf("failed ! mbedtls_ssl_handshake() returned -%#x\n\n", -rc);
	print_mbedtls_err(-rc);
      }
    } else {
      printf("New neighbour.\n");
      neighbour = malloc(sizeof(*neighbour));
      neighbour_init(neighbour, &dtls, &client_addr, listen_fd);
      neighbour->buf = buf;
      neighbour->len = rc;

      neighbour->next = neighbours;
      neighbours = neighbour;

      rc = mbedtls_ssl_set_client_transport_id(&neighbour->ssl,
					       client_addr.sin6_addr.s6_addr,
					       sizeof(client_addr.sin6_addr.s6_addr));
      if(rc) {
	printf("failed ! mbedtls_ssl_set_client_transport_id() returned -0x%x\n\n", -rc);
	print_mbedtls_err(rc);
      }

      mbedtls_ssl_set_bio(&neighbour->ssl, neighbour,
			  net_send, net_recv, net_recv_timeout);

      rc = mbedtls_ssl_handshake(&neighbour->ssl);
      if(rc == MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED) {
	printf("hello verification required\n");
	mbedtls_ssl_session_reset(&neighbour->ssl);
      } else if (rc) {
	printf("failed ! mbedtls_ssl_handshake() returned -%#x\n\n", -rc);
	print_mbedtls_err(-rc);
      }
    }
  }

  while (neighbours) {
    struct neighbour *n = neighbours->next;
    mbedtls_ssl_free( &n->ssl );
    free(neighbours);
    neighbours = n;
  }

  babel_dtls_free(&dtls);

  return rc < 0 ? 1 : 0;
}

#endif

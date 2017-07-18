CC=gcc
CFLAGS=-g -Wall -Wextra
# LDFLAGS=/home/antonin/mbedtls/pkg/mbedtls/usr/lib/libmbedcrypto.a \
# 	/home/antonin/mbedtls/pkg/mbedtls/usr/lib/libmbedtls.a \
# 	/home/antonin/mbedtls/pkg/mbedtls/usr/lib/libmbedx509.a

LDFLAGS=-lmbedx509 -lmbedcrypto -lmbedtls

CERTS=certs

all: dtls_client dtls_server dtls_server_mbedtls

dtls_client: dtls_client.o
	$(CC) -o $@ $^ $(LDFLAGS)

dtls_server: dtls_server.o
	$(CC) -o $@ $^ $(LDFLAGS)

dtls_server_mbedtls: dtls_server_mbedtls.o
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	rm -rf *.o

keygen:
	mkdir -p $(CERTS)
	openssl req -x509 -newkey rsa:2048 -days 3650 -nodes \
		-keyout $(CERTS)/a.key -out $(CERTS)/a.pem
	openssl req -x509 -newkey rsa:2048 -days 3650 -nodes \
		-keyout $(CERTS)/b.key -out $(CERTS)/b.pem
	openssl req -x509 -newkey rsa:2048 -days 3650 -nodes \
		-keyout $(CERTS)/c.key -out $(CERTS)/c.pem

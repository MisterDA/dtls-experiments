CC=gcc
CFLAGS=-g -Wall -Wextra 
LDFLAGS=-lmbedx509 -lmbedcrypto -lmbedtls

CERTS=certs

all: dtls_client dtls_server

dtls_client: dtls_client.o
	$(CC) -o $@ $^ $(LDFLAGS)

dtls_server: dtls_server.o
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) -o $@ -c $< $(CFLAGS)

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

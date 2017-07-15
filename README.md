# dtls-experiments

mbedTLS DTLS client/server, non-blocking, unconnected UDP sockets

Ongoing effort to understand DTLS and secure the [Babel routing
protocol][babel] and the [babeld][babeld]
daemon. [mbedTLS][mbedtls] is used for crypto and DTLS
implementation.

The server example should be non-blocking and use a single,
unconnected UDP socket.

[babel]: https://www.irif.fr/~jch/software/babel/
[babeld]: https://github.com/jech/babeld
[mbedtls]: https://tls.mbed.org/

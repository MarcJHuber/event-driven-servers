/*
 * conn.h
 *
 * Connection handling for TCP, UDP, TLS, DTLS
 *
 * (C)2025 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#ifndef __AAACLIENT_CONN_H__
#define __AAACLIENT_CONN_H__
//#include <stdlib.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include "misc/net.h"
#include "mavis/token.h"

struct conn {
    int fd;
    int socket_type;		// SOCK_STREAM, SOCK_DGRAM
    u_char tls_version;		// 0: None, 0x10: 1.0, 0x11: 1.1, 0x12, 0x13, ..., 0xff: any
    struct timeval tv;
    char *client_cert;
    char *client_key;
    char *client_key_pass;
    char *sni;
    u_char *alpn;
    u_int alpn_len;
    char *peer_cafile;
    sockaddr_union su_local;
    sockaddr_union su_peer;
    SSL *ssl;
    SSL_CTX *ctx;
    enum token protocol;
    uint32_t id;
    char *key;
    u_char *readbuf;
    size_t readbuf_len;
    size_t readbuf_off;
    int retries;
};

struct conn *conn_new(void);
void conn_free(struct conn *);

int conn_set_transport(struct conn *, enum token token);
void conn_set_tls_cert(struct conn *, char *cert);
void conn_set_tls_key(struct conn *, char *key);
void conn_set_tls_peer_sni(struct conn *, char *sni);
void conn_set_tls_alpn(struct conn *, char *alpn);
void conn_set_tls_peer_cn(struct conn *, char *cn);
void conn_set_tls_peer_san(struct conn *, char *san);
void conn_set_tls_peer_ca(struct conn *, char *cafile);
void conn_set_key(struct conn *, char *key);
void conn_init_timeout(struct conn *);
void conn_set_timeout(struct conn *, time_t tv_sec, suseconds_t tv_usec);
void conn_set_retries(struct conn *, int retries);
void conn_set_vrf(struct conn *, char *vrf);	// FIXME, not yet implemented

void conn_set_peer_addr(struct conn *, sockaddr_union * addr);
void conn_set_local_addr(struct conn *, sockaddr_union * addr);

int conn_set_peer(struct conn *, char *s);
int conn_set_local(struct conn *, char *s);

int conn_connect(struct conn *);
int conn_close(struct conn *);

ssize_t conn_read(struct conn *, void *buf, size_t cnt);
ssize_t conn_write(struct conn *, void *buf, size_t cnt);
ssize_t conn_readv(struct conn *, const struct iovec *iov, int iovcnt);
ssize_t conn_writev(struct conn *, const struct iovec *iov, int iovcnt);

#endif

/*
 * conn.c
 *
 * Connection handling for TCP, UDP, TLS, DTLS
 *
 * (C)2025 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include "conn.h"
#include <strings.h>

int conn_update_timeout(struct conn *conn)
{
    int res = -1;
    if (!conn->tv.tv_sec && !conn->tv.tv_usec)
	res = 0;
    else if (conn->fd > -1) {
	struct timeval now;
	gettimeofday(&now, NULL);
	struct timeval left;
	left.tv_sec = conn->tv.tv_sec - now.tv_sec - 1;
	left.tv_usec = conn->tv.tv_usec - now.tv_usec + 1000000;
	if (left.tv_usec > 999999) {
	    left.tv_sec += 1;
	    left.tv_usec -= 1000000;
	}
	if ((left.tv_sec == 0 && left.tv_usec > 0) || left.tv_sec > 0) {
	    res = 0;
	} else {
	    left.tv_sec = 0;
	    left.tv_usec = 1;
	}
	setsockopt(conn->fd, SOL_SOCKET, SO_SNDTIMEO, (const char *) &left, sizeof(left));
	setsockopt(conn->fd, SOL_SOCKET, SO_RCVTIMEO, (const char *) &left, sizeof(left));
    }
    return res;
}

void conn_set_timeout(struct conn *conn, time_t tv_sec, suseconds_t tv_usec)
{
    gettimeofday(&conn->tv, NULL);
    conn->tv.tv_sec += tv_sec;
    conn->tv.tv_usec += tv_usec;
    if (conn->tv.tv_usec > 1000000) {
	conn->tv.tv_sec++;
	conn->tv.tv_usec -= 1000000;
    }
    conn_update_timeout(conn);
}

void conn_set_retries(struct conn *conn, int retries)
{
    conn->retries = retries;
}

struct conn *conn_new(void)
{
    struct conn *conn = calloc(1, sizeof(struct conn));
    conn->fd = -1;
    conn->socket_type = SOCK_STREAM;
    conn_set_timeout(conn, 2, 0);
    return conn;
}

void conn_free(struct conn *conn)
{
    if (conn->client_cert)
	free(conn->client_cert);
    if (conn->client_key)
	free(conn->client_key);
    if (conn->client_key_pass)
	free(conn->client_key_pass);
    if (conn->sni)
	free(conn->sni);
    if (conn->alpn)
	free(conn->alpn);
    if (conn->peer_cafile)
	free(conn->peer_cafile);
    if (conn->readbuf)
	free(conn->readbuf);
    if (conn->key)
	free(conn->key);
    free(conn);
}

int conn_set_transport(struct conn *conn, enum token token)
{
    conn->tls_version = 0x00;
    switch (token) {
    case S_radius_tcp:
	conn->protocol = token;
	conn->socket_type = SOCK_STREAM;
	conn->tls_version = 0;
	return 0;
    case S_radius_tls:
	conn->protocol = token;
	conn->socket_type = SOCK_STREAM;
	conn->tls_version = 0x12;
	conn->key = strdup("radsec");
	return 0;
    case S_radius_dtls:
	conn->tls_version = 0x12;
	conn->protocol = token;
	conn->socket_type = SOCK_DGRAM;
	conn->key = strdup("radius/dtls");
	return 0;
    case S_radius_udp:
	conn->protocol = token;
	conn->socket_type = SOCK_DGRAM;
#define CONN_READBUF_SIZE 8192
	if (!conn->readbuf)
	    conn->readbuf = calloc(1, CONN_READBUF_SIZE);
	return 0;
    case S_tacacs_tls:
	conn->tls_version = 0x13;
	conn->protocol = token;
	conn->socket_type = SOCK_STREAM;
	conn->key = NULL;
	return 0;
    case S_tacacs_tcp:
	conn->protocol = token;
	conn->socket_type = SOCK_STREAM;
	return 0;
    default:
	conn->protocol = S_unknown;
	return -1;
    }
}

void conn_set_tls_alpn(struct conn *conn, char *alpn)
{
    if (conn->alpn)
	free(conn->alpn);
    conn->alpn_len = strlen(alpn) + 1;
    conn->alpn = calloc(1, conn->alpn_len);
    conn->alpn[0] = conn->alpn_len - 1;
    memcpy(conn->alpn + 1, alpn, conn->alpn_len - 1);
}

void conn_set_tls_cert(struct conn *conn, char *cert)
{
    if (conn->client_cert)
	free(conn->client_cert);
    conn->client_cert = strdup(cert);
}

void conn_set_tls_key(struct conn *conn, char *key)
{
    if (conn->client_key)
	free(conn->client_key);
    conn->client_key = strdup(key);
}

void conn_set_tls_keypass(struct conn *conn, char *keypass)
{
    if (conn->client_key_pass)
	free(conn->client_key_pass);
    conn->client_key = strdup(keypass);
}

void conn_set_tls_peer_sni(struct conn *conn, char *sni)
{
    if (conn->sni)
	free(conn->sni);
    conn->sni = strdup(sni);
}

void conn_set_tls_peer_ca(struct conn *conn, char *peer_cafile)
{
    if (conn->peer_cafile)
	free(conn->peer_cafile);
    conn->peer_cafile = strdup(peer_cafile);
}

void conn_set_peer_addr(struct conn *conn, sockaddr_union *addr)
{
    conn->su_peer = *addr;
}

void conn_set_local_addr(struct conn *conn, sockaddr_union *addr)
{
    conn->su_local = *addr;
}

int conn_set_peer(struct conn *conn, char *s)
{
    sockaddr_union su = { 0 };
    uint16_t port = 0;
    if (su_pton_p(&su, s, port))
	return -1;
    conn_set_peer_addr(conn, &su);
    return 0;
}

int conn_set_local(struct conn *conn, char *s)
{
    sockaddr_union su = { 0 };
    if (su_pton(&su, s))
	return -1;
    conn_set_local_addr(conn, &su);
    return 0;
}

void conn_set_key(struct conn *conn, char *key)
{
    if (conn->protocol == S_radius_dtls || conn->protocol == S_radius_tls || conn->protocol == S_tacacs_tls)
	return;
    if (conn->key)
	free(conn->key);
    conn->key = strdup(key);
}

static int pem_phrase_cb(char *buf, int size, int rwflag __attribute__((unused)), void *userdata)
{
    int i = (int) strlen((char *) userdata);

    if (i >= size)
	return 0;

    strcpy(buf, (char *) userdata);
    return i;
}

int conn_connect(struct conn *conn)
{
    if (conn->fd > -1)
	return -1;

    conn->fd = socket(conn->su_peer.sa.sa_family, conn->socket_type, 0);
    if (conn->fd < 0) {
	return -1;
    }

    if (su_bind(conn->fd, &conn->su_local)) {
	close(conn->fd);
	conn->fd = -1;
	return -1;
    }

    if (conn_update_timeout(conn))
	return -1;

    if (su_connect(conn->fd, &conn->su_peer)) {
	close(conn->fd);
	conn->fd = -1;
	return -1;
    }

    if (!conn->tls_version) {
	conn->alpn = NULL;
	return 0;
    }

    conn->ctx = SSL_CTX_new((conn->socket_type == SOCK_STREAM) ? TLS_client_method() : DTLS_client_method());
    if (!conn->ctx) {
	return -1;
    }

    SSL_CTX_set_options(conn->ctx, SSL_OP_ALL);

    if (conn->peer_cafile) {
#if OPENSSL_VERSION_NUMBER < 0x30000000
	if (SSL_CTX_load_verify_locations(conn->ctx, conn->peer_cafile, NULL) != 1) {
	    SSL_CTX_free(conn->ctx);
	    return -1;
	}
#else
	if (SSL_CTX_load_verify_file(conn->ctx, conn->peer_cafile) != 1) {
	    SSL_CTX_free(conn->ctx);
	    return -1;
	}
#endif
	SSL_CTX_set_verify_depth(conn->ctx, 8);
    } else
	SSL_CTX_set_verify_depth(conn->ctx, 0);

#if 1
    if (conn->sni || conn->peer_cafile)
	SSL_CTX_set_verify(conn->ctx, SSL_VERIFY_PEER, NULL);
// this currently breaks the connection.
#endif

    if (conn->client_key_pass) {
	SSL_CTX_set_default_passwd_cb(conn->ctx, pem_phrase_cb);
	SSL_CTX_set_default_passwd_cb_userdata(conn->ctx, conn->client_key_pass);
    }

    if (conn->client_cert) {
	if (!SSL_CTX_use_certificate_chain_file(conn->ctx, conn->client_cert)) {
	    SSL_CTX_free(conn->ctx);
	    return -1;
	}

	if (!SSL_CTX_use_PrivateKey_file(conn->ctx, conn->client_key ? conn->client_key : conn->client_cert, SSL_FILETYPE_PEM)) {
	    SSL_CTX_free(conn->ctx);
	    return -1;
	}

	if (!SSL_CTX_check_private_key(conn->ctx)) {
	    SSL_CTX_free(conn->ctx);
	    return -1;
	}
    }

    SSL_CTX_set_session_cache_mode(conn->ctx, SSL_SESS_CACHE_OFF);

    conn->ssl = SSL_new(conn->ctx);
    if (!conn->ssl) {
	SSL_CTX_free(conn->ctx);
	return -1;
    }

    if (conn->sni) {
	SSL_set_tlsext_host_name(conn->ssl, conn->sni);
	SSL_set1_host(conn->ssl, conn->sni);
    }
    if (conn->alpn) {
	if (SSL_set_alpn_protos(conn->ssl, conn->alpn, conn->alpn_len))
	    return -1;
    }
    if (!SSL_set_fd(conn->ssl, conn->fd)) {
	SSL_CTX_free(conn->ctx);
	SSL_free(conn->ssl);
	close(conn->fd);
	conn->fd = -1;
	return -1;
    }

    if (conn_update_timeout(conn))
	return -1;

    switch (conn->tls_version) {
    case 0x10:
	SSL_CTX_set_min_proto_version(conn->ctx, TLS1_VERSION);
	SSL_CTX_set_max_proto_version(conn->ctx, TLS1_VERSION);
	break;
    case 0x12:
	SSL_CTX_set_min_proto_version(conn->ctx, TLS1_2_VERSION);
	SSL_CTX_set_max_proto_version(conn->ctx, TLS1_2_VERSION);
	break;
    case 0x13:
	SSL_CTX_set_min_proto_version(conn->ctx, TLS1_3_VERSION);
	SSL_CTX_set_max_proto_version(conn->ctx, TLS1_3_VERSION);
	break;
    default:
	;
    }

    SSL_set_num_tickets(conn->ssl, 0);
    int res = SSL_connect(conn->ssl);
    if (res != 1) {
	// SSL_get_error(res)
	SSL_CTX_free(conn->ctx);
	SSL_free(conn->ssl);
	close(conn->fd);
	conn->fd = -1;
	return -1;
    }

    if (conn->peer_cafile && (SSL_get_verify_result(conn->ssl) != X509_V_OK)) {
	// SSL_get_error(res)
	SSL_CTX_free(conn->ctx);
	SSL_free(conn->ssl);
	close(conn->fd);
	conn->fd = -1;
	return -1;
    }

    if (conn->alpn) {
	const u_char *alpn_data = NULL;
	u_int alpn_data_len = 0;
	SSL_get0_alpn_selected(conn->ssl, &alpn_data, &alpn_data_len);
	if (alpn_data_len + 1 != conn->alpn_len || memcmp(alpn_data, conn->alpn + 1, alpn_data_len)) {
	    free(conn->alpn);
	    conn->alpn = NULL;
	    conn->alpn_len = 0;
	}
    }


    return 0;
}

int conn_close(struct conn *conn)
{
    int res = 0;
    if (conn->fd > -1) {
	conn_update_timeout(conn);
	if (conn->ssl) {
	    SSL_shutdown(conn->ssl);
	    SSL_free(conn->ssl);
	    conn->ssl = NULL;
	}
	if (conn->ctx) {
	    SSL_CTX_free(conn->ctx);
	    conn->ctx = NULL;
	}
	res = close(conn->fd);
	conn->fd = -1;
    }
    return res;
}

ssize_t conn_read(struct conn *conn, void *buf, size_t cnt)
{
    int len = 0;
    if (conn_update_timeout(conn))
	return -1;
    if (conn->readbuf) {
	if (cnt > conn->readbuf_len - conn->readbuf_off) {
	    len = recv(conn->fd, conn->readbuf + conn->readbuf_off, CONN_READBUF_SIZE - conn->readbuf_len, 0);
	    if (len < 1)
		return -1;
	    conn->readbuf_len += len;
	}
	if (cnt <= conn->readbuf_len - conn->readbuf_off) {
	    memcpy(buf, conn->readbuf + conn->readbuf_off, cnt);
	    conn->readbuf_off += cnt;
	    if (conn->readbuf_len == conn->readbuf_off) {
		conn->readbuf_len = 0;
		conn->readbuf_off = 0;
	    }
	    return cnt;
	}
	return -1;
    }

    if (conn->ssl)
	len = SSL_read(conn->ssl, buf, cnt);
    else
	len = read(conn->fd, buf, cnt);
    return len;
}


ssize_t conn_write(struct conn *conn, void *buf, size_t cnt)
{
    int len = 0;
    if (conn_update_timeout(conn))
	return -1;
    if (conn->ssl)
	len = SSL_write(conn->ssl, buf, cnt);
    else
	len = write(conn->fd, buf, cnt);
    return len;
}

ssize_t conn_readv(struct conn *conn, const struct iovec *iov, int iovcnt)
{
    int len = 0;
    if (conn->ssl) {
	for (int i = 0; i < iovcnt; i++) {
	    if (conn_update_timeout(conn))
		return len ? len : -1;
	    int l = SSL_read(conn->ssl, iov[i].iov_base, iov[i].iov_len);
	    if (l < 1)
		return len ? len : -1;
	    len += l;
	}
    } else {
	if (conn_update_timeout(conn))
	    return -1;
	len = readv(conn->fd, iov, iovcnt);
    }
    return len;
}

ssize_t conn_writev(struct conn *conn, const struct iovec *iov, int iovcnt)
{
    int len = 0;
    if (conn->ssl) {
	for (int i = 0; i < iovcnt; i++) {
	    if (conn_update_timeout(conn))
		return len ? len : -1;
	    int l = SSL_write(conn->ssl, iov[i].iov_base, iov[i].iov_len);
	    if (l < 1)
		return len ? len : -1;
	    len += l;
	}
    } else {
	if (conn_update_timeout(conn))
	    return -1;
	len = write(conn->fd, iov, iovcnt);
    }
    return len;
}

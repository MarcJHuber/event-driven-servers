/*
 * ssl_init.c
 * (C)1999-2011 by Marc Huber <Marc.Huber@web.de>
 *
 * $Id$
 *
 */

#include "misc/sysconf.h"
#include "mavis/log.h"
#include "mavis/debug.h"
#include "misc/ssl_init.h"
#include <string.h>
#include <sysexits.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

static const char rcsid[] __attribute__((used)) = "$Id$";

static void logssl(char *s)
{
    logmsg("%s: %s", s, ERR_error_string(ERR_get_error(), NULL));
    exit(EX_UNAVAILABLE);
}

static int pem_phrase_cb(char *buf, int size, int rwflag __attribute__((unused)), void *userdata)
{
    int i = 0;
    DebugIn(DEBUG_PROC);

    i = (int) strlen((char *) userdata);

    if (i >= size) {
	Debug((DEBUG_PROC, "- %s: i >= size\n", __func__));
	return 0;
    }

    strcpy(buf, (char *) userdata);
    Debug((DEBUG_PROC, "- %s == %d\n", __func__, i));
    return i;
}

SSL_CTX *ssl_init(char *cert_file, char *key_file, char *pem_phrase, char *ciphers)
{
    SSL_CTX *ctx;

    DebugIn(DEBUG_PROC);

    ctx = SSL_CTX_new(
#if OPENSSL_VERSION_NUMBER < 0x30000000
	SSLv23_server_method()
#else
	TLS_server_method()
#endif
    );
    if (!ctx)
	logssl("SSL_CTX_new");

#if 0
    /* potentially breaks more than it's worth */
    SSL_CTX_set_quiet_shutdown(ctx, 1);
#endif
    SSL_CTX_set_options(ctx, SSL_OP_ALL);
    if (ciphers && !SSL_CTX_set_cipher_list(ctx, ciphers))
	logssl("SSL_CTX_set_cipher_list");
    if (pem_phrase) {
	SSL_CTX_set_default_passwd_cb(ctx, pem_phrase_cb);
	SSL_CTX_set_default_passwd_cb_userdata(ctx, pem_phrase);
    }
    if (cert_file && !SSL_CTX_use_certificate_chain_file(ctx, cert_file))
	logssl("SSL_CTX_use_certificate_chain_file");
    if ((key_file || cert_file) && !SSL_CTX_use_PrivateKey_file(ctx, key_file ? key_file : cert_file, SSL_FILETYPE_PEM))
	logssl("SSL_CTX_use_PrivateKey_file");
    if ((key_file || cert_file) && !SSL_CTX_check_private_key(ctx))
	logssl("SSL_CTX_check_private_key");
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);

    DebugOut(DEBUG_PROC);
    return ctx;
}

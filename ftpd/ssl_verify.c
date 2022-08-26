/*
 * ssl_verify.c
 * (C)2002-2011 by Marc Huber <Marc.Huber@web.de>
 *
 * $Id$
 *
 */

#ifdef WITH_SSL

#include "misc/sysconf.h"
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

static const char rcsid[] __attribute__((used)) = "$Id$";

#if OPENSSL_VERSION_NUMBER >= 0x00907000L && !defined(OPENSSL_NO_X509_VERIFY)
#include "headers.h"
#include "misc/strops.h"

/* return value: != 0: Certificate verified */
static int app_verify_cb(X509_STORE_CTX * ctx, void *app_ctx)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000
    X509 *cert = ctx->cert;
#else
    X509 *cert = X509_STORE_CTX_get0_cert(ctx);
#endif
    if (cert && (X509_verify_cert(ctx) == 1)) {
	char buf[256];
	char *s = X509_NAME_oneline(X509_get_subject_name(cert),
				    buf, (int) sizeof(buf));
	if (s) {
#ifdef UNTESTED_CODE
	    STACK_OF(GENERAL_NAME) * gns;
#endif
	    strset(&((struct context *) app_ctx)->certsubj, s);
#if OPENSSL_VERSION_NUMBER < 0x10100000
	    ((struct context *) app_ctx)->certdepth = ctx->error_depth;
#else
	    ((struct context *) app_ctx)->certdepth = X509_STORE_CTX_get_error_depth(ctx);
#endif
	    /* logmsg ("peer cert subj: %s depth: %d", s, ctx->error_depth); */

#ifdef UNTESTED_CODE
/*
 * Not sure what do do with the alternate subject, yet, and whether
 * it's of any use evaluating it at all.                -MH20021006
 */
	    gns = X509_get_ext_d2i(ctx->cert, NID_subject_alt_name, NULL, NULL);
	    if (gns) {
		int i;
		for (i = 0; i < sk_GENERAL_NAME_num(gns) && !((struct context *) app_ctx)->certsubjaltname; i++) {
		    GENERAL_NAME *gn = sk_GENERAL_NAME_value(gns, i);
		    if (gn->type == GEN_EMAIL) {
			((struct context *) app_ctx)->certsubjaltname = Xcalloc(1, gn->d.ia5->length + 1);
			memcpy(((struct context *) app_ctx)->certsubjaltname, gn->d.ia5->data, gn->d.ia5->length);
		    }
		}
		sk_GENERAL_NAME_free(gns);
	    }
#endif
	    return 1;
	}
    }
    return ssl_auth_req ? 0 : 1;
}

static int verify_cb(int ok, X509_STORE_CTX * ctx)
{
    if (!ok) {
	X509 *xs = X509_STORE_CTX_get_current_cert(ctx);
	char buf[256];
	char *s = X509_NAME_oneline(X509_get_subject_name(xs), buf,
				    (int) sizeof(buf));

	if (s)
#if OPENSSL_VERSION_NUMBER < 0x10100000
	    logmsg("peer cert subj: %s depth: %d error: %d", s, ctx->error_depth, ctx->error);
#else
	    logmsg("peer cert subj: %s depth: %d error: %d", s, X509_STORE_CTX_get_error_depth(ctx), X509_STORE_CTX_get_error(ctx));
#endif

    }
    return ok;
}

void ssl_set_verify(SSL_CTX * ctx, void *app_ctx)
{
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE | (ssl_auth_req ? SSL_VERIFY_FAIL_IF_NO_PEER_CERT : 0), NULL);
    SSL_CTX_set_cert_verify_callback(ctx, app_verify_cb, app_ctx);
}

SSL_CTX *ssl_init_verify(SSL_CTX * ctx, int depth, char *cafile, char *capath)
{
    if (SSLeay() < 0x00907000L) {
	logmsg("Fatal: SSL library older than " OPENSSL_VERSION_TEXT);
	exit(EX_SOFTWARE);
    }

    if (cafile || capath) {
	if (!SSL_CTX_load_verify_locations(ctx, cafile, capath)) {
	    logmsg("SSL_CTX_load_verify_locations (%s, %s): %s",
		   cafile ? cafile : "<NULL>", capath ? capath : "<NULL>", ERR_error_string(ERR_get_error(), NULL));
	    return ctx;
	}
    } else if (!SSL_CTX_set_default_verify_paths(ctx)) {
	logmsg("SSL_CTX_set_default_verify_paths: %s", ERR_error_string(ERR_get_error(), NULL));
	return ctx;
    }

    if (cafile)
	SSL_CTX_set_client_CA_list(ctx, SSL_load_client_CA_file(cafile));
    else {
	logmsg("CA certificate file not specified.");
	logmsg("(see EXAMPLES in SSL_CTX_load_verify_locations man page)");
	exit(EX_UNAVAILABLE);
    }

    SSL_CTX_set_verify_depth(ctx, depth);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, verify_cb);
    return ctx;
}

#else
void ssl_set_verify(SSL_CTX * ctx __attribute__((unused)), void *app_ctx __attribute__((unused)))
{
}

SSL_CTX *ssl_init_verify(SSL_CTX * ctx, int depth __attribute__((unused)), char *cafile __attribute__((unused)), char *capath __attribute__((unused)))
{
    return ctx;
}
#endif

#endif				/* WITH_SSL */

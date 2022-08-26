/*
 * h_auth.c
 * (C)1998-2011 by Marc Huber <Marc.Huber@web.de>
 *
 * $Id$
 *
 */


#include "headers.h"
#ifdef WITH_SSL
#include "misc/ssl_init.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

void do_accept_c(struct context *ctx, int cur)
{
    int r;

    DebugIn(DEBUG_NET);

    io_sched_renew_proc(ctx->io, ctx, (void *) cleanup);

    io_clr_i(ctx->io, ctx->cfn);
    io_clr_o(ctx->io, ctx->cfn);

    switch (SSL_accept(ctx->ssl_c)) {
    default:			/* not completed */
	r = 0;
	io_set_cb_i(ctx->io, ctx->cfn, (void *) do_accept_c);
	io_set_cb_o(ctx->io, ctx->cfn, (void *) do_accept_c);

	if (SSL_want_read(ctx->ssl_c))
	    io_set_i(ctx->io, cur), r++;
	if (SSL_want_write(ctx->ssl_c))
	    io_set_o(ctx->io, cur), r++;

	if (!r) {
	    logmsg("SSL_accept(%s:%d): %s", __FILE__, __LINE__, ERR_error_string(ERR_get_error(), NULL));
	    cleanup(ctx, cur);
	}
	break;
    case 0:			/* failure, controlled shut down */
	cleanup(ctx, cur);
	break;
    case 1:			/* completed */
	if (ctx->use_tls_c)
	    print_banner(ctx);
	else {
	    io_set_cb_i(ctx->io, ctx->cfn, (void *) readcmd);
	    io_set_cb_o(ctx->io, ctx->cfn, (void *) control2socket);
	    io_set_i(ctx->io, ctx->cfn);
	}
	break;
    }
    DebugOut(DEBUG_NET);
}

static void do_accept_d(struct context *ctx, int cur)
{
    int r;
    DebugIn(DEBUG_NET);

    io_sched_renew_proc(ctx->io, ctx, (void *) cleanup);

    io_clr_i(ctx->io, cur);
    io_clr_o(ctx->io, cur);

    switch (SSL_accept(ctx->ssl_d)) {
    default:			/* not completed */
	Debug((DEBUG_NET, "SSL_get_error: %s\n", ERR_error_string(ERR_get_error(), NULL)));
	r = 0;

	io_set_cb_i(ctx->io, cur, (void *) do_accept_d);
	io_set_cb_o(ctx->io, cur, (void *) do_accept_d);

	if (SSL_want_read(ctx->ssl_d)) {
	    io_set_i(ctx->io, cur);
	    r++;
	}
	if (SSL_want_write(ctx->ssl_d)) {
	    io_set_o(ctx->io, cur);
	    r++;
	}

	if (!r) {
	    logmsg("SSL_accept(%s:%d): %s", __FILE__, __LINE__, ERR_error_string(ERR_get_error(), NULL));
	    cleanup(ctx, cur);
	}
	Debug((DEBUG_NET, "SSL handshake in progress.\n"));
	break;
    case 0:			/* failure, controlled shut down */
	Debug((DEBUG_NET, "SSL handshake failed.\n"));
	cleanup(ctx, cur);
	break;
    case 1:			/* completed */
	Debug((DEBUG_NET, "SSL connection established.\n"));
	do_connect_d(ctx, cur);
	break;
    }

    DebugOut(DEBUG_NET);
}

void sslify_c(struct context *ctx, int cur)
{
    Debug((DEBUG_NET, "%s.\n", __func__));
    if (!ctx->ssl_c) {
	if (ctx->cbufo && ctx->cbufo->length - ctx->cbufo->offset)
	    control2socket(ctx, cur);
	if (ctx->cbufo && ctx->cbufo->length - ctx->cbufo->offset)
	    io_set_cb_o(ctx->io, cur, (void *) sslify_c);
	else {
	    io_set_cb_e(ctx->io, cur, (void *) cleanup_control_ssl_error);
	    io_set_cb_h(ctx->io, cur, (void *) cleanup_control_ssl_error);
	    if (ssl_auth)
		ssl_set_verify(ssl_ctx, ctx);
	    ctx->ssl_c = SSL_new(ssl_ctx);
	    SSL_set_fd(ctx->ssl_c, ctx->cfn);
	    do_accept_c(ctx, cur);
	}
    }
}

void sslify_d(struct context *ctx, int cur)
{
    Debug((DEBUG_NET, "%s.\n", __func__));
    if (!ctx->ssl_d) {
	io_set_cb_e(ctx->io, cur, (void *) cleanup_data_ssl_error);
	io_set_cb_h(ctx->io, cur, (void *) cleanup_data_ssl_error);
	if (ssl_auth)
	    ssl_set_verify(ssl_ctx, ctx);
	ctx->ssl_d = SSL_new(ssl_ctx);
#if 0
	/* doesn't work as expected */
	if (ctx->ssl_c)
	    SSL_copy_session_id(ctx->ssl_d, ctx->ssl_c);
#endif
	SSL_set_fd(ctx->ssl_d, ctx->dfn);
	do_accept_d(ctx, cur);
    }
}

void h_auth(struct context *ctx, char *arg)
{
    DebugIn(DEBUG_COMMAND);
    if (!ssl_ctx)
	reply(ctx, MSG_500_AUTH_not_supported);
    else if (ctx->ssl_c)
	reply(ctx, MSG_501_AUTH_SSL_already_active);
    else if (!strcasecmp(arg, "ssl")) {
	ctx->protected_buffer_size = 0,	/* PBSZ 0 */
	    ctx->use_tls_d = 1;	/* PROT P */
	reply(ctx, ssl_old_draft ? MSG_334_AUTH_SSL_OK : MSG_234_AUTH_SSL_OK);
	sslify_c(ctx, ctx->cfn);
    } else if (!strcasecmp(arg, "tls-p")) {
	ctx->use_tls_d = 1;	/* PROT P */
	reply(ctx, ssl_old_draft ? MSG_334_AUTH_SSL_OK : MSG_234_AUTH_SSL_OK);
	sslify_c(ctx, ctx->cfn);
    } else if (!strcasecmp(arg, "tls") || !strcasecmp(arg, "tls-c")) {
	ctx->use_tls_d = 0;	/* PROT C */
	reply(ctx, ssl_old_draft ? MSG_334_AUTH_SSL_OK : MSG_234_AUTH_SSL_OK);
	sslify_c(ctx, ctx->cfn);
    } else
	reply(ctx, MSG_504_AUTH_type_not_supported);

    DebugOut(DEBUG_COMMAND);
}
#endif

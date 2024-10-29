/*
 * cleanup.c
 * (C)1999-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include "headers.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

void cleanup_one(struct context *ctx, int cur)
{
    if (cur > -1) {
	Debug((DEBUG_PROC, "cleanup_one(%d)\n", cur));

	io_clr_cb_i(ctx->io, cur);
	io_clr_cb_o(ctx->io, cur);

	io_close(ctx->io, cur);
    }
}

static void cleanup_context(struct context *ctx, int cur)
{
    if (cur < 0 || !ctx)
	return;

    Debug((DEBUG_PROC, "cleanup_context(%d)\n", cur));

    if (ctx->con_arr_idx > -1) {
	con_arr[ctx->con_arr_idx].use--;
	ctx->con_arr_idx = -1;
    }

    while (io_sched_pop(ctx->io, ctx));

    if (ctx->is_client)
	common_data.users_cur--;

    struct scm_data sd = {.type = SCM_DONE, .count = 1 }; //FIXME
    if (ctx->is_client && common_data.scm_send_msg(0, &sd, -1))
	die_when_idle = -1;

    if (common_data.users_cur == 0 && die_when_idle) {
	Debug((DEBUG_PROC, "exiting -- process out of use\n"));
	logmsg("Terminating, no longer needed.");
	exit(EX_OK);
    }

    free(ctx);

    set_proctitle(die_when_idle ? ACCEPT_NEVER : ACCEPT_YES);
}

static void cleanup_finish_o(struct context *ctx, int cur)
{
    /* cur == ctx->ofn */

    Debug((DEBUG_PROC, "cleanup_finish_o(%d)\n", cur));

    cleanup_one(ctx, cur);

    if (ctx->ifn > -1) {
	ctx->ofn = -1;
	if (!ctx->bufi)
	    cleanup(ctx, ctx->ifn);
	else
	    io_set_o(ctx->io, ctx->ifn);
    } else
	cleanup_context(ctx, cur);
}

static void cleanup_finish_i(struct context *ctx, int cur)
{
    /* cur == ctx->ifn */

    Debug((DEBUG_PROC, "cleanup_finish_i(%d)\n", cur));

    cleanup_one(ctx, cur);

    if (ctx->ofn > -1) {
	ctx->ifn = -1;
	Debug((DEBUG_PROC, "ctx->bufo = %p\n", ctx->bufo));
	if (!ctx->bufo)
	    cleanup(ctx, ctx->ofn);
	else
	    io_set_o(ctx->io, ctx->ofn);
    } else {
	cleanup_context(ctx, cur);
    }
}

#ifdef WITH_TLS
static void tls_cleanup(struct context *ctx, int cur)
{
    int r = 0;
    Debug((DEBUG_PROC, "ssl_cleanup\n"));
    io_clr_i(ctx->io, cur);
    io_clr_o(ctx->io, cur);
    io_set_cb_i(ctx->io, cur, (void *) tls_cleanup);
    io_set_cb_o(ctx->io, cur, (void *) tls_cleanup);
    switch (tls_close(ctx->ssl)) {
    case TLS_WANT_POLLIN:
	io_set_i(ctx->io, cur);
	r++;
	break;
    case TLS_WANT_POLLOUT:
	io_set_o(ctx->io, cur);
	r++;
	break;
    default:
	;
    }
    if (!r) {
	tls_free(ctx->ssl);
	ctx->ssl = NULL;
	cleanup_finish_i(ctx, cur);
    }
}
#else
#ifdef WITH_SSL
static void ssl_cleanup(struct context *ctx, int cur)
{
    int r = 0;
    Debug((DEBUG_PROC, "ssl_cleanup\n"));
    io_clr_i(ctx->io, cur);
    io_clr_o(ctx->io, cur);
    if (1 != SSL_shutdown(ctx->ssl)) {
	io_set_cb_i(ctx->io, cur, (void *) ssl_cleanup);
	io_set_cb_o(ctx->io, cur, (void *) ssl_cleanup);
	if (SSL_want_read(ctx->ssl)) {
	    io_set_i(ctx->io, cur);
	    r++;
	}
	if (SSL_want_write(ctx->ssl)) {
	    io_set_o(ctx->io, cur);
	    r++;
	}
    }
    if (!r) {
	SSL_free(ctx->ssl);
	ctx->ssl = NULL;
	cleanup_finish_i(ctx, cur);
    }
}
#endif
#endif				/* WITH_SSL */

void cleanup_error(struct context *ctx, int cur)
{
#ifdef WITH_TLS
    tls_free(ctx->ssl);
    ctx->ssl = NULL;
#else
#ifdef WITH_SSL
    SSL_free(ctx->ssl);
    ctx->ssl = NULL;
#endif				/* WITH_SSL */
#endif
    cleanup(ctx, cur);
}

void cleanup(struct context *ctx, int cur)
{
    Debug((DEBUG_PROC, "+ %s(%d)\n", __func__, cur));

    if (cur < 0)
	cur = ctx->ifn;
    if (cur < 0)
	cur = ctx->ofn;

    if (cur == ctx->ofn) {
	Debug((DEBUG_PROC, "line %d\n", __LINE__));

	ctx->bufo = buffer_free_all(ctx->bufo);
	cleanup_finish_o(ctx, cur);
    } else {			/* cur == ifn */

	Debug((DEBUG_PROC, "line %d\n", __LINE__));

	ctx->bufi = buffer_free_all(ctx->bufi);

#ifdef WITH_TLS
	if (ctx->ssl)
	    tls_cleanup(ctx, cur);
	else
#else
#ifdef WITH_SSL
	if (ctx->ssl)
	    ssl_cleanup(ctx, cur);
	else
#endif				/* WITH_SSL */
#endif				/* WITH_SSL */
	    cleanup_finish_i(ctx, cur);
    }

    DebugOut(DEBUG_PROC);
}

void cleanup_spawnd(struct context *ctx __attribute__((unused)), int cur __attribute__((unused)))
{
    if (common_data.users_cur == 0) {
	Debug((DEBUG_PROC, "exiting -- process out of use\n"));
	logmsg("Terminating, no longer needed.");
	exit(EX_OK);
    }
    die_when_idle = -1;
    set_proctitle(ACCEPT_NEVER);
}

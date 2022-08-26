/*
 * h_ccc.c
 *
 * (C)1998-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include "headers.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

static void do_shutdown(struct context *ctx, int cur)
{
    Debug((DEBUG_PROC, "do_shutdown\n"));

    if (io_SSL_shutdown(ctx->ssl_c, ctx->io, cur, (void *) do_shutdown)
	< 0 && errno == EAGAIN)
	return;

    io_clr_i(ctx->io, cur);
    io_clr_o(ctx->io, cur);

    SSL_free(ctx->ssl_c);
    ctx->ssl_c = NULL;

    io_set_cb_e(ctx->io, cur, (void *) cleanup_control);
    io_set_cb_h(ctx->io, cur, (void *) cleanup_control);
}

static void desslify(struct context *ctx, int cur)
{
    if (ctx->cbufo && ctx->cbufo->length - ctx->cbufo->offset)
	control2socket(ctx, cur);
    if (ctx->cbufo && ctx->cbufo->length - ctx->cbufo->offset)
	io_set_cb_o(ctx->io, cur, (void *) do_shutdown);
    else {
	io_clr_i(ctx->io, cur);
	io_clr_o(ctx->io, cur);
	do_shutdown(ctx, cur);
    }
}

void h_ccc(struct context *ctx, char *arg __attribute__((unused)))
{
    DebugIn(DEBUG_COMMAND);

    if (!ctx->ssl_c || ctx->use_tls_c)	/* no TLS or implicit TLS via port */
	reply(ctx, ctx->use_tls_c ? MSG_534_Denied : MSG_533_Denied);
    else {
	reply(ctx, MSG_200_Done);
	desslify(ctx, ctx->cfn);
    }

    DebugOut(DEBUG_COMMAND);
}

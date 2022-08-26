/*
 * bug.c
 *
 * (C)2003-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include "headers.h"

static void invalid_handler(struct context *ctx, int cur, char *which)
{
    logmsg("invalid %s handler called, trying to recover", which);
    if (cur == ctx->cfn) {
	logmsg("cleaning up control connection for fd %d", cur);
	cleanup_control(ctx, ctx->cfn);
    } else if (cur == ctx->dfn) {
	logmsg("cleaning up data connection for fd %d", cur);
	cleanup_data(ctx, ctx->dfn);
    } else if (cur == ctx->ffn) {
	logmsg("cleaning up file context for fd %d", cur);
	cleanup_file(ctx, ctx->ffn);
    } else {
	logmsg("unregistering unknown fd %d", cur);
	io_close(ctx->io, ctx->ffn);
    }
    cleanup(ctx_spawnd, 0);
    die_when_idle = -1;
    logmsg("Whatever just happened very much looks like a bug.");
    logmsg("The daemon will stop accepting new connections from spawnd.");
}

static void invalid_i(struct context *ctx, int cur)
{
    invalid_handler(ctx, cur, "input");
}

static void invalid_o(struct context *ctx, int cur)
{
    invalid_handler(ctx, cur, "output");
}

static void invalid_e(struct context *ctx, int cur)
{
    invalid_handler(ctx, cur, "error");
}

static void invalid_h(struct context *ctx, int cur)
{
    invalid_handler(ctx, cur, "hangup");
}

void setup_invalid_callbacks(io_context_t * io)
{
    io_set_cb_inv_i(io, (void *) invalid_i);
    io_set_cb_inv_o(io, (void *) invalid_o);
    io_set_cb_inv_e(io, (void *) invalid_e);
    io_set_cb_inv_h(io, (void *) invalid_h);
}

/*
 * h_quit.c
 *
 * (C)1998-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include "headers.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

void h_quit(struct context *ctx, char *arg __attribute__((unused)))
{
    DebugIn(DEBUG_COMMAND);
    io_clr_cb_i(ctx->io, ctx->cfn);
    /* ignore pending pasv connections */
    if (ctx->dfn > -1 && io_get_cb_i(ctx->io, ctx->dfn) == (void *) accept_data)
	cleanup_data(ctx, ctx->dfn);
    if (ctx->dfn > -1)
	reply(ctx, MSG_221_Control);
    file2control(ctx, "221", ctx->goodbye);
    reply(ctx, MSG_221_Goodbye);
    DebugOut(DEBUG_COMMAND);
}

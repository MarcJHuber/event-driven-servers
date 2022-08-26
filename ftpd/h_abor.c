/*
 * h_abor.c
 *
 * (C)1998-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include "headers.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

void h_abor(struct context *ctx, char *arg __attribute__((unused)))
{
    DebugIn(DEBUG_COMMAND);

    if (ctx->dfn > -1) {
	ftp_log(ctx, LOG_TRANSFER, "X");
	if (ctx->transfer_in_progress)
	    reply(ctx, MSG_426_Transfer_aborted);
	reply(ctx, MSG_226_ABOR_successful);
    } else
	reply(ctx, MSG_225_ABOR_successful);
    cleanup_data(ctx, ctx->dfn);
    cleanup_file(ctx, ctx->ffn);
    ctx->dbuf = buffer_free_all(ctx->dbuf);
    DebugOut(DEBUG_COMMAND);
}

/*
 * ident_buffer2socket.c
 *
 * (C)1999-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include "headers.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

void ident_buffer2socket(struct context *ctx, int cur __attribute__((unused)))
{
    ssize_t l;

    DebugIn(DEBUG_BUFFER);

    l = write(ctx->ifn, ctx->ident_buf + ctx->ident_bufoff, ctx->ident_buflen - ctx->ident_bufoff);
    if (l < 0) {
	if (errno != EAGAIN)
	    cleanup_ident(ctx, ctx->ifn);
    } else if (l == (int) (ctx->ident_buflen - ctx->ident_bufoff)) {
	ctx->ident_buflen = 0, ctx->ident_bufoff = 0;
	io_clr_o(ctx->io, ctx->ifn);
	io_set_i(ctx->io, ctx->ifn);
    } else if (l > 0)
	ctx->ident_bufoff += l;

    DebugOut(DEBUG_BUFFER);
}

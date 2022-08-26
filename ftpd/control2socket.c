/*
 * control2socket.c
 * (C)1998-2011 by Marc Huber <Marc.Huber@web.de>
 *
 * $Id$
 *
 */

#include "headers.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

void control2socket(struct context *ctx, int cur)
{
    struct buffer *b = ctx->cbufo;
    ssize_t i = 0;

    Debug((DEBUG_BUFFER, "+ %s (%d)\n", __func__, ctx->cfn));

    if (!b) {
	logmsg("FATAL: control2socket: Buffer is NULL!");
	cleanup_control(ctx, ctx->cfn);
    }
#ifdef WITH_SSL
    else if (ctx->ssl_c && !(i = io_SSL_write(ctx->ssl_c, b->buf + b->offset, b->length - b->offset, ctx->io, ctx->cfn, (void *) control2socket)))
	cleanup_control(ctx, ctx->cfn);
#endif
    else if (
#ifdef WITH_SSL
		!ctx->ssl_c &&
#endif
		!(i = write(ctx->cfn, b->buf + b->offset, b->length - b->offset)))
	cleanup_control(ctx, ctx->cfn);
    else if (i > 0) {
	b->offset += i;
	ctx->traffic_total += i;

	if (b->offset == b->length)
	    ctx->cbufo = buffer_free(ctx->cbufo);

	if (!ctx->cbufo) {
	    io_clr_o(ctx->io, ctx->cfn);
	    if (ctx->dfn < 0 && io_is_invalid_i(ctx->io, cur))
		cleanup_control(ctx, ctx->cfn);
	}
    } else if (errno != EAGAIN)
	cleanup(ctx, ctx->cfn);

    DebugOut(DEBUG_BUFFER);
}

/*
 * buffer2socket.c
 * (C)1999-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include "headers.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

void buffer2socket(struct context *ctx, int cur)
{
    size_t l;
    off_t o;
    int fd_in;
    struct buffer *b;

    DebugIn(DEBUG_BUFFER);

    io_sched_renew_proc(ctx->io, ctx, (void *) cleanup);

    if (cur == ctx->ifn)	/* read from bufi, write to ifn */
	fd_in = ctx->ofn, b = ctx->bufi;
    else			/* read from bufo, write to ofn */
	fd_in = ctx->ifn, b = ctx->bufo;

    if (!b) {			/* should not happen ... */
	cleanup(ctx, cur);
	Debug((DEBUG_BUFFER, "- %s: buffer empty\n", __func__));
	return;
    }
#ifdef WITH_TLS
    if (cur == ctx->ifn && ctx->ssl)
	l = io_TLS_write(ctx->ssl, b->buf + b->offset, b->length - b->offset, ctx->io, cur, (void *) buffer2socket);
    else
#else
#ifdef WITH_SSL
    if (cur == ctx->ifn && ctx->ssl)
	l = io_SSL_write(ctx->ssl, b->buf + b->offset, b->length - b->offset, ctx->io, cur, (void *) buffer2socket);
    else
#endif
#endif
	l = write(cur, b->buf + b->offset, b->length - b->offset);

    if (l <= 0) {
	if (errno != EAGAIN)
	    cleanup(ctx, cur);
	Debug((DEBUG_BUFFER, "- %s: Write error (%d)\n", __func__, cur));
	return;
    }
    o = (off_t) l;
    b = buffer_release(b, &o);

    if (cur == ctx->ifn)	/* read from bufi, write to ifn */
	ctx->bufi = b;
    else			/* read from bufo, write to ofn */
	ctx->bufo = b;

    if (!b) {
	io_clr_o(ctx->io, cur);
	if (fd_in < 0)
	    cleanup(ctx, cur);
	else
	    io_set_i(ctx->io, fd_in);
    }

    DebugOut(DEBUG_BUFFER);
}

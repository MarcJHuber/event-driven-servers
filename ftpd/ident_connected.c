/*
 * ident_connected.c
 *
 * (C)1999-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include "headers.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

void ident_connected(struct context *ctx, int cur __attribute__((unused)))
{
    DebugIn(DEBUG_NET);

    io_set_cb_o(ctx->io, ctx->ifn, (void *) ident_buffer2socket);
    io_set_cb_i(ctx->io, ctx->ifn, (void *) ident_socket2buffer);

    ctx->ident_bufoff = 0;
    ctx->ident_buf = Xcalloc(MAXBUFSIZE1413, 1);

    ctx->ident_buflen = snprintf(ctx->ident_buf, MAXBUFSIZE1413, "%d, %d\r\n", su_get_port(&ctx->sa_c_remote), su_get_port(&ctx->sa_c_local));

    Debug((DEBUG_NET, "RFC1413 query: \"%s\"\n", ctx->ident_buf));

    io_clr_i(ctx->io, ctx->ifn);
    io_set_o(ctx->io, ctx->ifn);

    DebugOut(DEBUG_NET);
}

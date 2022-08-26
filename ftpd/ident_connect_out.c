/*
 * ident_connect_out.c
 *
 * (C)1999-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include "headers.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

void ident_connect_out(struct context *ctx, int cur __attribute__((unused)))
{
    sockaddr_union su;

    DebugIn(DEBUG_COMMAND);

    ctx->ifn = socket(ctx->sa_c_local.sa.sa_family, SOCK_STREAM, IPPROTO_TCP);

    if (ctx->ifn < 0) {
	logerr("socket (%s:%d)", __FILE__, __LINE__);
	DebugOut(DEBUG_COMMAND);
	return;
    }

    io_register(ctx->io, ctx->ifn, ctx);
    io_set_cb_e(ctx->io, ctx->ifn, (void *) cleanup_ident);
    io_set_cb_h(ctx->io, ctx->ifn, (void *) cleanup_ident);

    fcntl(ctx->ifn, F_SETFL, O_NONBLOCK);
    fcntl(ctx->ifn, F_SETFD, FD_CLOEXEC);

    su = ctx->sa_c_local;
    su_set_port(&su, 0);

    if (0 > su_bind(ctx->ifn, &su)) {
	logerr("bind (%s:%d)", __FILE__, __LINE__);
	cleanup_ident(ctx, ctx->ifn);
    } else {
	su = ctx->sa_c_remote;
	su_set_port(&su, 113);

	if (su_connect(ctx->ifn, &su) < 0)
	    switch (errno) {
	    case EINPROGRESS:
		io_set_cb_o(ctx->io, ctx->ifn, (void *) ident_connected);
		io_clr_cb_i(ctx->io, ctx->ifn);
		io_set_o(ctx->io, ctx->ifn);
		io_clr_i(ctx->io, ctx->ifn);
		break;
	    default:
		if (errno != ECONNREFUSED)
		    logerr("connect (%s:%d)", __FILE__, __LINE__);
		cleanup_ident(ctx, ctx->ifn);
	} else
	    ident_connected(ctx, ctx->ifn);
    }
    DebugOut(DEBUG_COMMAND);
}

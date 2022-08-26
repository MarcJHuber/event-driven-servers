/*
 * h_esta.c
 *
 * (C)2002-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include "headers.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

void h_esta(struct context *ctx, char *arg __attribute__((unused)))
{
    sockaddr_union su;
    socklen_t sulen = (socklen_t) sizeof(su);

    DebugIn(DEBUG_COMMAND);

    if (ctx->passive_transfer)
	reply(ctx, MSG_520_Not_active);
    else {
	if (ctx->dfn < 0)
	    connect_port(ctx);

	if (ctx->dfn < 0 || getsockname(ctx->dfn, &su.sa, &sulen))
	    reply(ctx, MSG_425_Cant_open_dataconnection);
	else {
	    char buf[160];

	    if (ctx->passive_addr)
		su_copy_addr(&su, ctx->passive_addr);

	    replyf(ctx, MSG_225_Connected_from, rfc2428_str(&su, buf, sizeof(buf)));
	}
    }

    DebugOut(DEBUG_COMMAND);
}

void h_estp(struct context *ctx, char *arg __attribute__((unused)))
{
    DebugIn(DEBUG_COMMAND);

    if (!ctx->passive_transfer)
	reply(ctx, MSG_520_Not_passive);
    else if (arg && *arg && rfc2428_eval(&ctx->sa_d_estp, arg) < 0)
	reply(ctx, MSG_501_Syntax_error);
    else {
	sockaddr_union su;
	socklen_t sulen = (socklen_t) sizeof(su);

	ctx->estp = 1;

	if (arg && *arg)
	    ctx->estp_valid = 1;

	if (ctx->dfn > -1 && io_get_cb_i(ctx->io, ctx->dfn) == (void *) accept_data) {
	    io_set_cb_e(ctx->io, ctx->dfn, (void *) cleanup_data);
	    io_set_cb_h(ctx->io, ctx->dfn, (void *) cleanup_data);
	    accept_data(ctx, ctx->dfn);
	}

	if (ctx->dfn < 0 || getpeername(ctx->dfn, &su.sa, &sulen))
	    reply(ctx, MSG_425_Dataconnection_not_open);
	else {
	    char buf[160];
	    replyf(ctx, MSG_225_Connected_to, rfc2428_str(&su, buf, sizeof(buf)));
	}
    }

    DebugOut(DEBUG_COMMAND);
}

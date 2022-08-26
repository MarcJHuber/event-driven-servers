/*
 * h_site_idle.c
 *
 * (C)2000-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include "headers.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

void h_site_idle(struct context *ctx, char *arg)
{
    DebugIn(DEBUG_COMMAND);

    if (arg) {
	u_long t;
	if (1 == sscanf(arg, "%lu", &t)) {
	    if ((time_t) t < ctx->idle_timeout_min || (time_t) t > ctx->idle_timeout_max)
		replyf(ctx, MSG_501_Inactivity_range, ctx->idle_timeout_min, ctx->idle_timeout_max);
	    else {
		io_sched_del(ctx->io, ctx, (void *) cleanup);
		ctx->idle_timeout = (time_t) t;
		if (t)
		    io_sched_app(ctx->io, ctx, (void *) cleanup, (time_t) t, 0);
		replyf(ctx, MSG_200_Inactivity_set, ctx->idle_timeout);
	    }
	} else
	    reply(ctx, MSG_500_Inactivity);
    } else
	replyf(ctx, MSG_200_Current_inactivity, ctx->idle_timeout);

    DebugOut(DEBUG_COMMAND);
}

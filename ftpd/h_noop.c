/*
 * h_noop.c
 * (C)1998-2011 by Marc Huber <Marc.Huber@web.de>
 *
 * $Id$
 *
 */

#include "headers.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

void h_noop(struct context *ctx, char *arg __attribute__((unused)))
{
    struct timeval *tv = NULL;
    time_t left = -1;

    if (ctx->idle_timeout && (tv = io_sched_peek_time(ctx->io, ctx)))
	left = tv->tv_sec - io_now.tv_sec;

    if (!tv || left < 0)
	reply(ctx, MSG_200_Command_okay);
    else if (left == 1)
	reply(ctx, MSG_200_Command_okay_remaining_1);
    else
	replyf(ctx, MSG_200_Command_okay_remaining_n, left);
}

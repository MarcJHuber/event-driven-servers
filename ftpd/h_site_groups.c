/*
 * h_site_groups.c
 *
 * (C)2000-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include "headers.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

void h_site_groups(struct context *ctx, char *arg __attribute__((unused)))
{
    DebugIn(DEBUG_COMMAND);

    reply(ctx, MSG_214_Group_membership);

    if (ctx->gids_size) {
	int i;
	for (i = 0; i < ctx->gids_size; i++)
	    replyf(ctx, "214-  %u\r\n", (u_int) ctx->gids[i]);
    } else
	replyf(ctx, "214-  %u\r\n", (u_int) ctx->gid);

    reply(ctx, "214\r\n");

    DebugOut(DEBUG_COMMAND);
}

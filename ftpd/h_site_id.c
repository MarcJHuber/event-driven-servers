/*
 * h_site_id.c
 *
 * (C)1998-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include "headers.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

void h_site_id(struct context *ctx, char *arg __attribute__((unused)))
{
    DebugIn(DEBUG_COMMAND);

    replyf(ctx, "200 uid=%lu(%s) gid=%lu(%s)", (u_long) ctx->uid, lookup_uid(ctx, ctx->uid), (u_long) ctx->gid, lookup_gid(ctx, ctx->gid));

    if (ctx->gids_size) {
	int i;

	reply(ctx, " groups=");
	for (i = 0; i < ctx->gids_size; i++)
	    replyf(ctx, "%s%lu(%s)", i ? "," : "", (u_long) ctx->gids[i], lookup_gid(ctx, ctx->gids[i]));
    }

    reply(ctx, "\r\n");

    DebugOut(DEBUG_COMMAND);
}

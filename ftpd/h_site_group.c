/*
 * h_site_group.c
 *
 * (C)1998-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include "headers.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

void h_site_group(struct context *ctx, char *arg)
{
    int i = NGROUPS_MAX;
    u_int u;

    DebugIn(DEBUG_COMMAND);

    if (1 == sscanf(arg, "%u", &u))
	for (i = 0; i < ctx->gids_size && (gid_t) u != ctx->gids[i]; i++);
    else
	for (i = 0; i < ctx->gids_size && strcmp(arg, lookup_gid(ctx, ctx->gids[i])); i++);

    if (i < ctx->gids_size) {
	ctx->gid = ctx->gids[i];
	reply(ctx, MSG_200_Group_id_changed);
    } else if (i == ctx->gids_size)
	replyf(ctx, MSG_501_Syntax, MSG_SITE_GROUP);
    else
	reply(ctx, MSG_550_Group_id_deny);

    DebugOut(DEBUG_COMMAND);
}

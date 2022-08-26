/*
 * h_site_umask.c
 *
 * (C)1998-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include "headers.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

void h_site_umask(struct context *ctx, char *arg)
{
    DebugIn(DEBUG_COMMAND);

    if (arg && (1 == sscanf(arg, "%o", &ctx->umask)))
	ctx->umask_set = 1;

    replyf(ctx, MSG_200_umask, ctx->umask);

    DebugOut(DEBUG_COMMAND);
}

/*
 * h_rest.c
 *
 * (C)1998-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include "headers.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

void h_rest(struct context *ctx, char *arg)
{
    unsigned long long off;

    DebugIn(DEBUG_COMMAND);

    if (1 == sscanf(arg, "%llu", &off)) {
	ctx->io_offset = off;
	replyf(ctx, MSG_350_Restarting, (unsigned long long) ctx->io_offset);
    } else
	replyf(ctx, MSG_501_Syntax, MSG_REST);
    DebugOut(DEBUG_COMMAND);
}

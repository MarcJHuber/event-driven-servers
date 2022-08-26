/*
 * h_rmd.c
 *
 * (C)1998-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include "headers.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

void h_rmd(struct context *ctx, char *arg)
{
    char *t;
    struct stat st;

    DebugIn(DEBUG_COMMAND);

    if ((t = buildpath(ctx, arg)) && (strlen(t) > ctx->rootlen) && !pickystat(ctx, &st, t) && S_ISDIR(st.st_mode) && !rmdir(t))
	reply(ctx, MSG_250_Directory_removed);
    else
	reply(ctx, MSG_550_Permission_denied);

    DebugOut(DEBUG_COMMAND);
}

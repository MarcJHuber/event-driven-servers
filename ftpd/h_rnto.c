/*
 * h_rnto.c
 *
 * (C)1998-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include "headers.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

void h_rnto(struct context *ctx, char *arg)
{
    char *t;
    struct stat st;

    DebugIn(DEBUG_COMMAND);

    if (!ctx->last_command_was_rnfr)
	reply(ctx, MSG_503_Use_RNFR_first);
    else if ((t = buildpath(ctx, arg)) && !pickystat_path(ctx, &st, t) && (stat(t, &st), !rename(ctx->filename, t))) {
	if (S_ISREG(st.st_mode))
	    quota_add(ctx, -st.st_size);

	reply(ctx, MSG_250_File_renamed);
	ctx->filename[0] = 0;
    } else
	reply(ctx, MSG_550_Permission_denied);

    ctx->last_command_was_rnfr = 0;

    DebugOut(DEBUG_COMMAND);
}

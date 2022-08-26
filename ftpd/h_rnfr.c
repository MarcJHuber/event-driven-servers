/*
 * h_rnfr.c
 *
 * (C)1998-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include "headers.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

void h_rnfr(struct context *ctx, char *arg)
{
    char *t;
    struct stat st;

    DebugIn(DEBUG_COMMAND);

    if ((t = buildpath(ctx, arg)) && (strlen(t) > ctx->rootlen) && (!pickystat(ctx, &st, t)) && (S_ISREG(st.st_mode) || S_ISDIR(st.st_mode))) {
	ctx->last_command_was_rnfr = 1;

	if (strlen(t) >= sizeof(ctx->filename)) {
	    logerr("buffer too small in %s:%d (%s/%s)", __FILE__, __LINE__, ctx->user, t);
	    reply(ctx, MSG_551_Internal_error);
	    cleanup_data(ctx, ctx->dfn);
	    DebugOut(DEBUG_COMMAND);
	    return;
	}
	strcpy(ctx->filename, t);
	reply(ctx, MSG_350_Awaiting_dest);
    } else
	reply(ctx, MSG_550_No_such_file);

    DebugOut(DEBUG_COMMAND);
}

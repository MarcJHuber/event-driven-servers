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

void h_rang(struct context *ctx, char *arg)
{
    unsigned long long off_start;
    unsigned long long off_end;

    DebugIn(DEBUG_COMMAND);

    if (ctx->use_ascii) {
	reply(ctx, MSG_452_Command_not_for_ascii);
    } else if (2 == sscanf(arg, "%llu %llu", &off_start, &off_end)) {
	if (off_start == 1 && off_end == 0) {
	    ctx->io_offset = 0;
	    ctx->io_offset_start = 0;
	    ctx->io_offset_end = -1;
	    reply(ctx, MSG_350_Reset_rang);
	} else if (off_start > off_end) {
	    replyf(ctx, MSG_501_Syntax, MSG_RANG);
	} else {
	    ctx->io_offset = off_start;
	    ctx->io_offset_start = off_start;
	    ctx->io_offset_end = off_end;
	    replyf(ctx, MSG_350_Restarting_rang, off_start, off_end);
	}
    } else
	replyf(ctx, MSG_501_Syntax, MSG_RANG);
    DebugOut(DEBUG_COMMAND);
}

/*
 * h_pbsz.c
 *
 * (C)2000-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include "headers.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

void h_pbsz(struct context *ctx, char *arg)
{
    unsigned pbs;

    DebugIn(DEBUG_COMMAND);

    if (!ctx->ssl_c)
	reply(ctx, MSG_503_Security_data_exchange_incomplete);
    else if (1 != sscanf(arg, "%u", &pbs))
	reply(ctx, MSG_501_Syntax_error);
    else {
	reply(ctx, "200 PBSZ=0\r\n");
	ctx->protected_buffer_size = 0;
    }
    DebugOut(DEBUG_COMMAND);
}

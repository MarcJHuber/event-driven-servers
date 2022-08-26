/*
 * h_host.c
 * (C)1999-2011 by Marc Huber <Marc.Huber@web.de>
 *
 * $Id$
 *
 */

/*
 * The HOST command was specified until draft-ietf-ftpext-mlst-08.txt,
 * but has been removed from later versions of the draft. It may be
 * specified in its own draft sometime.
 *
 */

#include "headers.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

void h_host(struct context *ctx, char *arg)
{
    Debug((DEBUG_COMMAND, "+ %s %s\n", __func__, arg));

    if (ctx->state != ST_conn)
	reply(ctx, MSG_503_Already_logged_in);
    else {
	strset(&ctx->vhost, arg);
	reply(ctx, MSG_220_Virtual_host_set);
    }

    DebugOut(DEBUG_COMMAND);
}

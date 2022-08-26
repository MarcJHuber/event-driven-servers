/*
 * h_user.c
 *
 * (C)1998-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include "headers.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

void h_user(struct context *ctx, char *arg)
{
    char *host;

    DebugIn(DEBUG_COMMAND);

    if (ctx->state == ST_conn) {
	ctx->state = ST_user;

	host = strchr(arg, '@');
	if (host) {
	    *host++ = 0;
	    strset(&ctx->vhost, host);
	}

	if (!strcasecmp(arg, "ftp") || !strcasecmp(arg, "anonymous")) {
	    reply(ctx, MSG_331_anon);
	    strset(&ctx->user, "ftp");
	    ctx->anonymous = 1;
	} else {
	    reply(ctx, MSG_331_user);
	    strset(&ctx->user, arg);
	    ctx->anonymous = 0;
	}
    } else
	reply(ctx, MSG_503_Already_logged_in);

    DebugOut(DEBUG_COMMAND);
}

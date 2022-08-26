/*
 * ident_socket2buffer.c
 *
 * (C)1999-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include "headers.h"
#include "foobar.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

void ident_socket2buffer(struct context *ctx, int cur)
{
    ssize_t l;

    DebugIn(DEBUG_NET);

    l = read(cur, ctx->ident_buf + ctx->ident_buflen, MAXBUFSIZE1413 - ctx->ident_buflen - 1);

    if (l > 0) {
	char *t;

	ctx->ident_buflen += l;
	ctx->ident_buf[ctx->ident_buflen] = 0;
	if ((t = strstr(ctx->ident_buf, "\r\n"))) {
	    int rp, lp;
	    *t = 0;
	    Debug((DEBUG_PROC, "RFC1413 answer: \"%s\"\n", ctx->ident_buf));

	    if (2 == sscanf(ctx->ident_buf, " %d , %d :", &rp, &lp) && su_get_port(&ctx->sa_c_local) == lp && su_get_port(&ctx->sa_c_remote) == rp) {
		char buf[160];
		char *u = rfc2428_str(&ctx->sa_c_remote, buf, sizeof(buf));
		if (u) {
		    t = alloca(strlen(u) + 1);
		    strcpy(t, u);
		}
		u = strchr(ctx->ident_buf, ':');
		if (u)
		    do
			u++;
		    while (*u && isspace((int) *u));

		if (ctx->loglevel & LOG_IDENT)
		    logmsg("%s->%s: %s", t ? t : "", rfc2428_str(&ctx->sa_c_local, buf, sizeof(buf)), u ? u : ctx->ident_buf);

		if (u && !strncasecmp("USERID", u, 6)) {
		    u += 6;
		    while (*u && isspace((int) *u))
			u++;
		    if (*u == ':') {
			do
			    u++;
			while (*u && *u != ':');
			if (*u) {
			    do
				u++;
			    while (*u && isspace((int) *u));
			    if (*u)
				strset(&ctx->ident_user, u);
			}
		    }
		}
	    }

	    cleanup_ident(ctx, cur);
	} else if (ctx->ident_buflen == MAXBUFSIZE1413 - 1)	/* response too long */
	    cleanup_ident(ctx, cur);
    } else if (!l || (l < 0 && errno != EAGAIN))
	cleanup_ident(ctx, cur);

    DebugOut(DEBUG_NET);
}

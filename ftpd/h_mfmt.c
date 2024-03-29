/*
 * h_mfmt.c
 *
 * (C)2002-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include "headers.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

void h_mfmt(struct context *ctx, char *arg)
{
    char *t;
    struct stat st;
    struct tm tm = { 0 };

    DebugIn(DEBUG_COMMAND);

    t = arg;

    while (*arg && !isspace((int) *arg))
	arg++;

    if (!isspace((int) *arg)) {
	reply(ctx, MSG_500_arguments_required);
	DebugOut(DEBUG_COMMAND);
	return;
    }

    *arg++ = 0;

    if (*arg && 6 == sscanf(t, "%4d%2d%2d%2d%2d%2d", &tm.tm_year, &tm.tm_mon, &tm.tm_mday, &tm.tm_hour, &tm.tm_min, &tm.tm_sec)) {
	struct utimbuf ut;
	tm.tm_year -= 1900;
	tm.tm_mon--;
	ut.modtime = mktime(&tm);

	if ((t = buildpath(ctx, arg)) && (!pickystat(ctx, &st, t))
	    && (S_ISREG(st.st_mode) || S_ISDIR(st.st_mode))
	    && st.st_uid == ctx->uid) {
	    ut.actime = st.st_atime;
	    if (utime(t, &ut))
		reply(ctx, MSG_550_Permission_denied);
	    else {
		struct stat sst;
		char u[40];
		if (stat(t, &sst))
		    sst.st_mtime = ut.modtime;
		strftime(u, sizeof(u), "213 Modify=%Y%m%d%H%M%S; ", gmtime(&sst.st_mtime));
		replyf(ctx, "%s%s\r\n", u, t);
	    }
	} else
	    reply(ctx, MSG_550_Permission_denied);
    } else
	reply(ctx, MSG_500_missing_filename);

    DebugOut(DEBUG_COMMAND);
}

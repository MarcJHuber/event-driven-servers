/*
 * h_mdtm.c
 * (C)1999-2011 by Marc Huber <Marc.Huber@web.de>
 *
 * $Id$
 *
 */

#include "headers.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

void h_mdtm(struct context *ctx, char *arg)
{
    char *t;
    struct stat st;

    DebugIn(DEBUG_COMMAND);

    if ((t = buildpath(ctx, arg)) && (!pickystat(ctx, &st, t))) {
	if (S_ISREG(st.st_mode)) {
	    char buffer[40];
	    struct tm *tm = gmtime(&st.st_mtime);
	    strftime(buffer, (size_t) 40, "%Y%m%d%H%M%S", tm);
	    replyf(ctx, "213 %s\r\n", buffer);
	} else
	    reply(ctx, MSG_550_Not_plain_file);
    } else
	reply(ctx, MSG_550_No_such_file_or_directory);

    DebugOut(DEBUG_COMMAND);
}

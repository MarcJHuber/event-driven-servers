/*
 * h_mff.c
 *
 * (C)2002-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include "headers.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

void h_mff(struct context *ctx, char *arg)
{
    char *t;

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

    if (*arg) {
	char *u, *v;
	int flags = 0;
#define flag_modify	1
#define flag_unix_mode	2
#define flag_unix_group	4
	time_t modify = 0;
	mode_t unix_mode = 0;
	gid_t unix_group = 0;

	for (; (u = strtok(t, ";")); t = NULL)
	    if (*u && (v = strchr(u, '='))) {
		*v++ = 0;

		if (!strcasecmp(u, "Modify")) {
		    struct tm tm;
		    memset(&tm, 0, sizeof(tm));

		    if (6 != sscanf(v, "%4d%2d%2d%2d%2d%2d", &tm.tm_year, &tm.tm_mon, &tm.tm_mday, &tm.tm_hour, &tm.tm_min, &tm.tm_sec))
			goto syntax_error;
		    tm.tm_year -= 1900;
		    tm.tm_mon--;
		    flags |= flag_modify;
		    modify = mktime(&tm);
		} else if (!strcasecmp(u, "UNIX.mode")) {
		    u_int mode;
		    if (1 != sscanf(v, "%o", &mode))
			goto syntax_error;
		    flags |= flag_unix_mode;
		    unix_mode = (mode_t) mode;

		} else if (!strcasecmp(u, "UNIX.group")) {
		    int i = NGROUPS_MAX;
		    u_int ug;

		    if (1 == sscanf(v, "%u", &ug))
			for (i = 0; i < ctx->gids_size && (gid_t) ug != ctx->gids[i]; i++);
		    else
			for (i = 0; i < ctx->gids_size && strcmp(arg, lookup_gid(ctx, ctx->gids[i])); i++);

		    if (i < ctx->gids_size) {
			flags |= flag_unix_group;
			unix_group = (gid_t) i;
		    }
		} else {
		    replyf(ctx, MSG_504_Parameter_not_implemented, u);
		    goto bye;
		}
	    } else if (*u) {
	      syntax_error:
		reply(ctx, MSG_501_Syntax_error);
		goto bye;
	    }

	if (flags) {
	    struct stat st;
	    if ((t = buildpath(ctx, arg)) && (!pickystat(ctx, &st, t))
		&& (S_ISREG(st.st_mode) || S_ISDIR(st.st_mode))) {
		if ((flags & flag_modify) && st.st_uid == ctx->uid) {
		    struct utimbuf ut;
		    ut.actime = st.st_atime;
		    ut.modtime = modify;
		    utime(t, &ut);
		}

		if (flags & ~flag_modify) {
		    int fn = open(t, O_RDONLY | O_NOFOLLOW);
		    if (fn > -1) {
			if (!fstat(fn, &st) && st.st_uid == ctx->uid) {
			    if (flags & flag_unix_group) {
				seteuid(0);
				if (fchown(fn, (uid_t) - 1, unix_group)) {
				    // FIXME
				}
				seteuid(ctx->uid);
			    }
			    if (flags & flag_unix_mode)
				fchmod(fn, unix_mode | (S_ISDIR(st.st_mode)
							? ctx->chmod_dirmask : ctx->chmod_filemask));
			    fstat(fn, &st);

			}
			close(fn);
		    }
		} else
		    stat(t, &st);

		reply(ctx, "213 ");
		if (flags & flag_modify) {
		    char s[30];
		    strftime(s, sizeof(s), "%Y%m%d%H%M%S", gmtime(&st.st_mtime));
		    replyf(ctx, "Modify=%s;", s);
		}

		if (flags & flag_unix_mode)
		    replyf(ctx, "UNIX.mode=0%o;", 0777 & (u_int) st.st_mode);

		if (flags & flag_unix_group)
		    replyf(ctx, "UNIX.group=%s;", lookup_gid(ctx, st.st_gid));

		replyf(ctx, " %s\r\n", arg);
	    } else
		reply(ctx, MSG_550_Permission_denied);
	} else
	    replyf(ctx, "213  %s\r\n", arg);
    } else
	reply(ctx, MSG_500_missing_filename);

  bye:
    DebugOut(DEBUG_COMMAND);
}

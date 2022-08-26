/*
 * h_cwd.c
 * (C)1998-2011 by Marc Huber <Marc.Huber@web.de>
 *
 * $Id$
 *
 */

#include "headers.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

void h_cwd(struct context *ctx, char *arg)
{
    char *t = NULL, *u = NULL;
    struct stat st;
    int r = -1;

    Debug((DEBUG_COMMAND, "+ %s %s\n", __func__, arg));

    if (arg[0] == '.' && arg[1] == '.' && !arg[2]) {
	for (u = ctx->cwd + ctx->cwdlen; u > ctx->cwd + ctx->rootlen && *u != '/'; u--);
	if (*u != '/')
	    u = NULL;
    }

  again:

    if (u) {
	*u = 0;
	ctx->cwdlen = (u_int) (u - ctx->cwd);
	acl_conf_readme(ctx);
	file2control(ctx, "250", ctx->readme);
	replyf(ctx, MSG_250_Dir_changed, ctx->cwdlen == ctx->rootlen ? "/" : ctx->cwd + ctx->rootlen);
    } else if ((t = buildpath(ctx, arg)) && !(r = pickystat(ctx, &st, t)) && S_ISDIR(st.st_mode)) {
	if ((st.st_mode & S_IXOTH) || ((st.st_mode & S_IXUSR) && (st.st_uid == ctx->uid)) || ((st.st_mode & S_IXGRP) && check_gids(ctx, st.st_gid))) {
	    u_int l = (u_int) strlen(t);

	    if (ctx->cwdlen >= sizeof(ctx->cwd)) {
		logerr("buffer too small in %s:%d (%s/%s)", __FILE__, __LINE__, ctx->user, t);
		reply(ctx, MSG_551_Internal_error);
		DebugOut(DEBUG_COMMAND);
		return;
	    }
	    strcpy(ctx->cwd, t);
	    ctx->cwdlen = l;
	    acl_conf_readme(ctx);
	    file2control(ctx, "250", ctx->readme);
	    replyf(ctx, MSG_250_Dir_changed, ctx->cwdlen == ctx->rootlen ? "/" : ctx->cwd + ctx->rootlen);
	} else
	    reply(ctx, MSG_550_Permission_denied);
    } else {
	if (r && (arg[0] == '~') && (arg[1] == '/' || !arg[1])) {
	    char *c = alloca(ctx->homelen - ctx->rootlen + strlen(arg) + 3);

	    strcpy(c, "/");
	    strcat(c, ctx->home + ctx->rootlen);
	    strcat(c, "/");
	    strcat(c, arg + 1);
	    arg = c;
	    goto again;
	}

	reply(ctx, MSG_501_No_such_dir);
    }

    DebugOut(DEBUG_COMMAND);
}

void h_cdup(struct context *ctx, char *arg __attribute__((unused)))
{
    h_cwd(ctx, "..");
}

/*
 * pickystat.c
 *
 * (C)1998-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include "headers.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

static int pickystat_one(struct context *ctx, struct stat *st, char *file)
{
    struct stat lst;

    Debug((DEBUG_PROC, "+ %s(%s)\n", __func__, file));

    if (lstat(file, &lst)) {
	/* file doesn't exist */

	Debug((DEBUG_PROC, "- %s FAILURE (no such file)\n", __func__));
	return -1;
    }

    if (S_ISLNK(lst.st_mode)) {
	/* symbolic link */

	if (stat(file, st)) {
	    Debug((DEBUG_PROC, "- %s FAILURE (broken link)\n", __func__));
	    return -1;
	}

	if (!(((ctx->allow_symlinks & SYMLINKS_YES)) ||
	      ((ctx->allow_symlinks & SYMLINKS_REAL) && !ctx->anonymous) ||
	      ((ctx->allow_symlinks & SYMLINKS_ROOT) && lst.st_uid == 0) || ((ctx->allow_symlinks & SYMLINKS_SAME)
									     && lst.st_uid == st->st_uid))) {
	    Debug((DEBUG_PROC, "- %s FAILURE (unsafe symlink)\n", __func__));
	    return -1;
	}
    } else
	*st = lst;

    if (!S_ISREG(st->st_mode) && !S_ISDIR(st->st_mode)) {
	Debug((DEBUG_PROC, "- %s FAILURE (not a plain file or directory)\n", __func__));
	return -1;
    }

    if (ctx->picky_uidcheck && !ctx->picky_gidcheck && (st->st_uid != ctx->uid)) {
	Debug((DEBUG_PROC, "- %s FAILURE (UID check)\n", __func__));
	return -1;
    }

    if (ctx->picky_gidcheck && !check_gids(ctx, st->st_gid)) {
	Debug((DEBUG_PROC, "- %s FAILURE (GID check)\n", __func__));
	return -1;
    }

    if (ctx->picky_permcheck && !(st->st_mode & S_IROTH)) {
	Debug((DEBUG_PROC, "- %s FAILURE (not world readable)\n", __func__));
	return -1;
    }

    Debug((DEBUG_PROC, "- %s SUCCESS\n", __func__));
    return 0;
}

int pickystat(struct context *ctx, struct stat *st, char *path)
{
    int r;

    Debug((DEBUG_PROC, "+ %s (%s)\n", __func__, path));

    if (*path == '/') {
	int offset;
	char *t;

	if (strncmp(path, ctx->cwd, ctx->cwdlen) || (path[ctx->cwdlen] && path[ctx->cwdlen] != '/'))
	    offset = ctx->rootlen;
	else
	    offset = ctx->cwdlen;

	offset = offset ? offset : 1;

	for (t = path + offset; *t; t++)
	    if (*t == '/') {
		*t = 0;
		r = pickystat_one(ctx, st, path);
		*t = '/';
		if (r) {
		    DebugOut(DEBUG_PROC);
		    return r;
		}
	    }
    }

    r = pickystat_one(ctx, st, path);
    DebugOut(DEBUG_PROC);
    return r;
}

int pickystat_path(struct context *ctx, struct stat *st, char *path)
{
    char *t;
    int r;

    t = strrchr(path, '/');
    if (t)
	*t = 0;
    r = pickystat(ctx, st, path);
    if (t)
	*t = '/';
    return r;
}

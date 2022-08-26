/*
 * path.c
 *
 * (C)1998-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include "headers.h"
#include <grp.h>

static const char rcsid[] __attribute__((used)) = "$Id$";

char *parsepath(struct context *ctx, char *path)
{
    static char tmp[PATH_MAX + 1];
    char *t = tmp;

    Debug((DEBUG_PATH, "+ %s(\"%s\")\n", __func__, path));

    while (*path) {
	if (*path == '/') {
	    if (*++path == '/')
		continue;

	    if (*path == '.') {
		path++;
		if (*path == '/' || *path == 0)
		    continue;

		if (*path == '.' && (*(path + 1) == '/' || *(path + 1) == 0)) {
		    if (t == tmp) {
			Debug((DEBUG_PATH, "- %s = NULL\n", __func__));
			return NULL;
		    }
		    path++;
		    if (*t == '/' && t > tmp)
			t--;
		    while (t > tmp && *t != '/')
			t--;
		    if ((u_int) (t - tmp) < ctx->rootlen) {
			if (t == tmp && ctx->rootlen == 0) {
			    tmp[1] = '/', tmp[0] = 0;
			    Debug((DEBUG_PATH, "- %s = \"/\"\n", __func__));
			    return tmp;
			}
			Debug((DEBUG_PATH, "- %s = NULL\n", __func__));
			return NULL;
		    }
		    continue;
		}
		path--;
	    }
	    path--;
	}
	*t++ = *path++;
    }

    do
	*t-- = 0;
    while (t >= tmp && *t == '/');

    if (!tmp[0])
	tmp[0] = '/', tmp[1] = 0;

    Debug((DEBUG_PATH, "- %s = %s\n", __func__, tmp));
    return tmp;
}

char *buildpath(struct context *ctx, char *path)
{
    static char tmp[PATH_MAX + 1];
    char *t = tmp, *c = tmp;
#if defined(WITH_PCRE) || defined(WITH_PCRE2)
    static char pcretmp[PATH_MAX + 1];
#endif				/* WITH_PCRE */

    Debug((DEBUG_PATH, "+ %s(\"%s\")\n", __func__, path));
    Debug((DEBUG_PATH, "  cwd =\"%s\"\n", ctx->cwd));

    if (!path || (ctx->cwdlen + strlen(path) + 3 > PATH_MAX)) {
	Debug((DEBUG_PATH, "- %s = NULL\n", __func__));
	return NULL;
    }

    if ((size_t) snprintf(tmp, sizeof(tmp), "%s/%s", path[0] == '/' ? ctx->root : ctx->cwd, path) >= sizeof(tmp)) {
	Debug((DEBUG_PATH, "- %s: path too long\n", __func__));
	return NULL;
    }

    while (*c)
	if (*c == '/' && *(c + 1) == '/')
	    c++;
	else
	    *t++ = *c++;

    if (t > tmp + 1 && *(t - 1) == '/')
	t--;
    *t = 0;

    t = parsepath(ctx, tmp);

    if ((!t || strncmp(t, ctx->root, ctx->rootlen)) ||
	(ctx->rootlen && t[ctx->rootlen] && (t[ctx->rootlen] != '/')) || (!ctx->allow_dotfiles && strstr(t, "/."))) {
	Debug((DEBUG_PATH, "- %s = NULL\n", __func__));
	return NULL;
    }
#if defined(WITH_PCRE) || defined(WITH_PCRE2)
    if (t && PCRE_exec(t, pcretmp, sizeof(pcretmp)))
	t = *pcretmp ? pcretmp : NULL;
#endif				/* WITH_PCRE */
    Debug((DEBUG_PATH, "- %s = %s\n", __func__, t ? t : "NULL"));
    return t;
}

/* check_incoming: returns TRUE if valid upload path */

int check_incoming(struct context *ctx, char *path, u_int mask)
{
    char *t;
    struct stat st;
    Debug((DEBUG_PATH, "  check_incoming %s\n", path));
    Debug((DEBUG_PATH, "  test1 %d\n", ctx->incoming ? 1 : 0));
    Debug((DEBUG_PATH, "  test2 %s\n", strrchr(path, '/')));

    if (!ctx->incoming || !(t = strrchr(path, '/')) || regexec(ctx->incoming, path, 0, NULL, 0))
	return 0;
    *t = 0;
    Debug((DEBUG_PATH, "  regex passed"));
    if (stat(path, &st)) {
	*t = '/';
	return 0;
    }
    *t = '/';
    seteuid(0);
    setgroups(0, NULL);
    setegid(st.st_gid);
    seteuid(st.st_uid);
    current_uid = st.st_uid;
    current_gid = st.st_gid;
    update_ids = -1;
    ctx->umask = mask ? mask : (u_int) (~(st.st_mode & 0777) | 022);
    Debug((DEBUG_PATH, "  umask set to %.4o\n", ctx->umask));
    return -1;
}

/*
 * readme.c
 *
 * (C)1998-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include "headers.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

#define VD_SIZE 32		/* good enough for the cyclic buffer */

struct visited_dirs {
    int size;
    int current;
    struct {
	long dev;
	long ino;
    } cyc[VD_SIZE];
};

static int dir_visited(struct context *ctx, struct stat *st)
{
    int i = 0;

    if (!ctx->visited_dirs)
	ctx->visited_dirs = Xcalloc(1, sizeof(struct visited_dirs));
    else
	for (i = 0; i < ctx->visited_dirs->size; i++)
	    if (ctx->visited_dirs->cyc[i].ino == (long) st->st_ino && ctx->visited_dirs->cyc[i].dev == (long) st->st_dev)
		return -1;

    ctx->visited_dirs->cyc[ctx->visited_dirs->current].dev = (long) st->st_dev;
    ctx->visited_dirs->cyc[ctx->visited_dirs->current].ino = (long) st->st_ino;

    if (ctx->visited_dirs->size < VD_SIZE)
	ctx->visited_dirs->size++;

    if (++ctx->visited_dirs->current == VD_SIZE)
	ctx->visited_dirs->current = 0;

    return 0;
}

void file2control(struct context *ctx, char *arg, char *file)
{
    Debug((DEBUG_PROC, "+ %s (%s)\n", __func__, file ? file : "(NULL)"));

    if (file && ctx->multiline_banners) {
	int i = -1;
	struct stat st;
	int is_banner = file == ctx->welcome || file == ctx->banner || file == ctx->goodbye;
	char form[PATH_MAX + 1], path[PATH_MAX + 1];
	char *l, *t, llang[10];

	if (!is_banner && ctx->readme_once && (!pickystat(ctx, &st, ctx->cwd)) && dir_visited(ctx, &st)) {
	    Debug((DEBUG_PROC, "already visited\n"));
	    DebugOut(DEBUG_PROC);
	    return;
	}

	l = llang, t = lang[ctx->lang];
	*l++ = '-';
	while (*t)
	    *l++ = tolower((int) *t++);
	*l = 0;

	if ((sizeof(form) <= (size_t) snprintf(form, sizeof(form), "%s/%s", (is_banner || file[0] == '/')
					       ? "" : ctx->cwd, file)) || (sizeof(path) <= (size_t) snprintf(path, sizeof(path), form, llang))) {
	    DebugOut(DEBUG_PROC);
	    return;
	}

	if (is_banner) {
	    i = open(path, O_RDONLY);
	    if (i < 0 && strstr(form, "%s")) {
		if (sizeof(path) <= (size_t) snprintf(path, sizeof(path), form, "")) {
		    DebugOut(DEBUG_PROC);
		    return;
		}
		i = open(path, O_RDONLY);
	    }
	} else {
	    if (((pickystat(ctx, &st, path) || (i = open(path, O_RDONLY)) < 0)) && strstr(form, "%s")) {
		if (sizeof(path) <= (size_t) snprintf(path, sizeof(path), form, "")) {
		    DebugOut(DEBUG_PROC);
		    return;
		}
		if (!pickystat(ctx, &st, path))
		    i = open(path, O_RDONLY);
	    }

	    if (i > -1 && ctx->readme_notify) {
		long days_ago = (io_now.tv_sec - st.st_mtime) / 86400;
		char tb[2 * PATH_MAX];
		close(i);

		replyf(ctx, "%s-", arg);
		replyf(ctx, MSG_Readme_notify_1, file);

		strftime(tb, sizeof(tb), MSG_Readme_notify_2, localtime(&st.st_mtime));
		replyf(ctx, "%s-%s", arg, tb);

		if (days_ago == 1)
		    reply(ctx, MSG_Readme_notify_31);
		else
		    replyf(ctx, MSG_Readme_notify_3n, days_ago);

		DebugOut(DEBUG_PROC);
		return;
	    }
	}

	if (i > -1) {
	    char tbuf[BUFSIZE];
	    char *lineend, *linestart = NULL;
	    size_t offset = 0;
	    ssize_t inlength;

	    while ((inlength = read(i, tbuf + offset, sizeof(tbuf) - 1 - offset)) > 0) {
		inlength += offset;
		tbuf[inlength] = 0;
		linestart = tbuf;
		while ((lineend = strchr(linestart, '\n'))) {
		    *lineend = 0;
		    chomp(linestart);
		    replyf(ctx, "%s-%s\r\n", arg, cook(ctx, linestart, NULL, NULL, 0));
		    linestart = lineend + 1;
		}
#ifdef README_LOOP
/*
 * Don't allow arbitrary sized README files. Noone's able or willing to
 * read thousands of lines rushing by. BUFSIZE is our upper limit. For
 * unlimited file sizes, #define README_LOOP. Yes, that could be made
 * a configuration option. No, I don't think it makes sense.
 */
		if ((offset = tbuf + inlength - linestart))
		    memmove(tbuf, linestart, offset);
		else
#endif
		    break;
	    }
	    close(i);
	}
    }
    DebugOut(DEBUG_PROC);
}

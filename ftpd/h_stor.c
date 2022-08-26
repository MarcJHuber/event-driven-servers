/*
 * h_stor.c
 * (C)1998-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include "headers.h"
#include "misc/base64.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

static void skipbytes(struct context *ctx, int cur __attribute__((unused)))
{
    off_t ro = ctx->io_offset, off = 0;

    DebugIn(DEBUG_BUFFER);

    sigbus_cur = ctx->cfn;

    if (chunk_get(ctx, NULL)) {
	io_sched_pop(ctx->io, ctx);
	ctx->dbufi = buffer_free_all(ctx->dbufi);
	ctx->remaining = 0, ctx->offset = 0;
	cleanup_file(ctx, ctx->ffn);
	cleanup_data(ctx, ctx->ffn);
	reply(ctx, MSG_451_Internal_error);
    } else {
	if (chunk_remaining(ctx)) {
	    char *u = ctx->chunk_start;
	    char lastchar = ctx->lastchar;
	    size_t len = MIN(ctx->chunk_length, (size_t) bufsize);
	    char *ul = u + len;

	    for (off = 0; ro && u < ul; ro--, off++, lastchar = *u++)
		if (*u == '\n' && lastchar != '\r')
		    ro--;

	    ctx->lastchar = lastchar;
	    chunk_release(ctx, len);
	}

	if (!chunk_remaining(ctx))
	    ro = 0;

	if (!ro) {
	    ctx->dbufi = buffer_free_all(ctx->dbufi);
	    lseek(ctx->ffn, ctx->offset + off, SEEK_SET);
	    ctx->remaining = 0, ctx->offset = 0;

	    if (io_get_cb_i(ctx->io, ctx->dfn) == (void *) socket2buffer) {
		/* already connected */
		io_clr_o(ctx->io, ctx->dfn);
		io_set_i(ctx->io, ctx->dfn);
	    }
	    io_sched_pop(ctx->io, ctx);
	} else
	    io_sched_renew_proc(ctx->io, ctx, (void *) skipbytes);

	ctx->io_offset = ro;
    }

    DebugOut(DEBUG_BUFFER);
}

static void strrandom(char *s, int len)
{
    size_t i, bl = 4 * ((len + 2) / 3), tl = len + 8;
    char *t = alloca(tl);
    size_t j = sizeof(u_int) * bl;
    size_t *b = alloca(j);

    for (i = 0; i < bl; i++)
	b[i] = rand();

    base64enc((char *) b, bl, t, &tl);

    strncpy(s, t, len);
    s[len - 1] = 0;
}

static int myopen(char *pathname, int flags, mode_t mode, int stou)
{
    if (stou) {
	int fn, tries = 0;
	char *p = pathname;
	for (; *p; p++);
	if (p - pathname > 5) {
	    p -= 6;
	    do {
		strrandom(p, 6);
		fn = open(pathname, flags, mode);
		if (fn > -1)
		    return fn;
	    }
	    while (++tries < 100 && fn < 0 && errno == EEXIST);
	}
	return -1;
    }
    return open(pathname, flags, mode);
}

static void h_xstor(struct context *ctx, char *arg, int flags)
{
    char *t;
    int f = -1;
    struct stat st;
    int stou = 0;
    char tbuf[PATH_MAX + 13];

    DebugIn(DEBUG_COMMAND);

    if (ctx->transfer_in_progress) {
	reply(ctx, MSG_501_Transfer_in_progress);
	DebugOut(DEBUG_COMMAND);
	return;
    }

    ctx->outgoing_data = 0;
    if (ctx->dfn > -1 && io_get_cb_i(ctx->io, ctx->dfn) == (void *) accept_data) {
	io_set_i(ctx->io, ctx->dfn);
	io_clr_o(ctx->io, ctx->dfn);
	io_set_cb_e(ctx->io, ctx->dfn, (void *) cleanup_data);
	io_set_cb_h(ctx->io, ctx->dfn, (void *) cleanup_data);
    }

    quota_add(ctx, 0);

    if (ctx->quota_path && (ctx->quota_ondisk >= ctx->quota_limit)) {
	reply(ctx, MSG_451_quota_exceeded);
	logmsg("%s: quota limit reached", ctx->user);
	DebugOut(DEBUG_COMMAND);
	return;
    }

    if (!arg) {
	stou = -1;
	snprintf(tbuf, sizeof(tbuf), "%s/stou.XXXXXX", ctx->cwd);
	arg = tbuf;

	t = buildpath(ctx, arg);
    } else if (acl_binary_only(ctx, arg, (t = buildpath(ctx, arg)))) {
	reply(ctx, MSG_504_no_ascii);
	cleanup_data_reuse(ctx, ctx->dfn);
	DebugOut(DEBUG_COMMAND);
	return;
    }

    st.st_size = 0;

    if (t)
	acl_set_umask(ctx, arg, t);

    if (ctx->anonymous || stou)
	flags |= O_EXCL;

    if (t && (!ctx->anonymous || check_incoming(ctx, t, 077)) &&
	!pickystat_path(ctx, &st, t) &&
	(stat(t, &st), (f = myopen(t, O_RDWR | O_CREAT | O_LARGEFILE | O_NOFOLLOW | flags, ctx->chmod_filemask | (0644 & ~ctx->umask), stou)) > -1)) {

	fcntl(f, F_SETFD, FD_CLOEXEC);

	ctx->quota_filesize_before_stor = st.st_size;
	ctx->quota_update_on_close = 1;

	if (ctx->dfn < 0)
	    connect_port(ctx);

	if (ctx->dfn < 0) {
	    reply(ctx, MSG_431_Opening_datacon_failed);
	    close(f);
	    ctx->dbuf = buffer_free_all(ctx->dbuf);
	    DebugOut(DEBUG_COMMAND);
	    return;
	}

	ctx->ffn = f;
	if (strlen(t) >= sizeof(ctx->filename)) {
	    logerr("buffer too small in %s:%d (%s/%s)", __FILE__, __LINE__, ctx->user, t);
	    reply(ctx, MSG_551_Internal_error);
	    close(f);
	    cleanup(ctx, ctx->dfn);
	    ctx->dbuf = buffer_free_all(ctx->dbuf);
	    DebugOut(DEBUG_COMMAND);
	    return;
	}
	strcpy(ctx->filename, t);
	ctx->filesize = 0;
	ctx->bytecount = 0;

	if (io_get_cb_i(ctx->io, ctx->dfn) == (void *) socket2buffer || is_connected(ctx->dfn)) {
	    if (stou)
		replyf(ctx, "125 FILE: %s\r\n", ctx->filename + ctx->rootlen);
	    else
		replyf(ctx, MSG_125_Starting_dc, ctx->use_ascii ? "ASCII" : "BINARY", ctx->use_tls_d ? "TLS " : "");
	} else {
	    if (stou)
		replyf(ctx, "150 FILE: %s\r\n", ctx->filename + ctx->rootlen);
	    else
		replyf(ctx, MSG_150_Opening_dc, ctx->use_ascii ? "ASCII" : "BINARY", ctx->use_tls_d ? "TLS " : "");
	}

	ctx->transfer_in_progress = 1;

	if (ctx->io_offset) {
	    if (ctx->use_ascii) {
		ctx->offset = 0;
		ctx->remaining = st.st_size;
		io_sched_add(ctx->io, ctx, (void *) skipbytes, 0, 0);
#ifdef WITH_MMAP
		if (use_mmap)
		    ctx->iomode = IOMODE_mmap;
		else
#endif
		    ctx->iomode = IOMODE_read, ctx->iomode_fixed = 1;
	    } else {
		lseek(f, ctx->io_offset, SEEK_SET);
		ctx->io_offset = 0;
	    }
	}

	if (io_get_cb_i(ctx->io, ctx->dfn) == (void *) socket2buffer) {
	    /* already connected */
	    io_clr_o(ctx->io, ctx->dfn);
	    io_set_i(ctx->io, ctx->dfn);
	}

	ctx->transferstart = io_now.tv_sec;
	ctx->count_files++;
    } else {
	if (stou && errno == EEXIST)
	    reply(ctx, MSG_451_unique_file_failure);
	else
	    reply(ctx, MSG_550_Permission_denied);
	cleanup_data_reuse(ctx, ctx->dfn);
    }

    DebugOut(DEBUG_COMMAND);
}

void h_stor(struct context *ctx, char *arg)
{
    DebugIn(DEBUG_COMMAND);
    h_xstor(ctx, arg, (ctx->io_offset ? 0 : O_TRUNC));
    DebugOut(DEBUG_COMMAND);
}

void h_stou(struct context *ctx, char *arg __attribute__((unused)))
{
    DebugIn(DEBUG_COMMAND);
    ctx->io_offset = 0;
    h_xstor(ctx, NULL, O_TRUNC);
    DebugOut(DEBUG_COMMAND);
}

void h_appe(struct context *ctx, char *arg)
{
    DebugIn(DEBUG_COMMAND);
    ctx->io_offset = 0;
    h_xstor(ctx, arg, O_APPEND);
    DebugOut(DEBUG_COMMAND);
}

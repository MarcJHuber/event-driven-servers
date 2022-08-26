/*
 * h_size.c
 * (C)1998-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include "headers.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

static void getasciisize(struct context *ctx, int cur __attribute__((unused)))
{
    DebugIn(DEBUG_BUFFER);

    sigbus_cur = ctx->cfn;
    if (chunk_get(ctx, NULL)) {
	reply(ctx, MSG_451_Internal_error);
	goto bye;
    } else {
	if (chunk_remaining(ctx)) {
	    char lastchar = ctx->lastchar;
	    char *u = ctx->chunk_start;
	    size_t len = MIN(ctx->chunk_length, (size_t) bufsize);
	    char *ul = u + len;

	    for (; u < ul; lastchar = *u++)
		if (*u == '\n' && lastchar != '\r')
		    ctx->bytecount++;

	    ctx->lastchar = lastchar;
	    ctx->bytecount += len;
	    chunk_release(ctx, len);
	}

	if (chunk_remaining(ctx))
	    io_sched_renew_proc(ctx->io, ctx, (void *) getasciisize);
	else {
	    replyf(ctx, "213 %llu\r\n", (unsigned long long) ctx->bytecount);
	  bye:
	    ctx->lastchar = 0, ctx->bytecount = 0;
	    io_sched_pop(ctx->io, ctx);
	    cleanup_file(ctx, ctx->ffn);
	    ctx->dbufi = buffer_free_all(ctx->dbufi);
	}
    }

    DebugOut(DEBUG_BUFFER);
}

void h_size(struct context *ctx, char *arg)
{
    char *t;
    struct stat st;

    DebugIn(DEBUG_COMMAND);

    if (ctx->use_ascii && ctx->ffn > -1)
	reply(ctx, MSG_452_Command_not_during_transfers);
    else if (!((t = buildpath(ctx, arg)) && !pickystat(ctx, &st, t)))
	reply(ctx, MSG_550_No_such_file_or_directory);
    else if (!S_ISREG(st.st_mode))
	reply(ctx, MSG_550_Not_plain_file);
    else if (ctx->use_ascii && acl_binary_only(ctx, arg, t))
	reply(ctx, MSG_504_size_no_ascii);
    else if (ctx->use_ascii && ctx->ascii_size_limit > -1 && ctx->ascii_size_limit < st.st_size)
	reply(ctx, MSG_504_size_ascii_exceeded);
    else if (ctx->use_ascii && ((ctx->ffn = open(t, O_RDONLY | O_LARGEFILE)) > -1)) {
	fcntl(ctx->ffn, F_SETFD, FD_CLOEXEC);
	ctx->iomode_fixed = 0;
	io_sched_add(ctx->io, ctx, (void *) getasciisize, 0, 0);
#ifdef WITH_MMAP
	if (use_mmap)
	    ctx->iomode = IOMODE_mmap;
	else
#endif
	    ctx->iomode = IOMODE_read, ctx->iomode_fixed = 1;
	ctx->offset = 0;
	ctx->remaining = st.st_size;
	ctx->bytecount = 0;
	ctx->quota_update_on_close = 0;
    } else if (!ctx->use_ascii)
	replyf(ctx, "213 %llu\r\n", (unsigned long long) st.st_size);
    else
	reply(ctx, MSG_550_No_such_file_or_directory);

    DebugOut(DEBUG_COMMAND);
}

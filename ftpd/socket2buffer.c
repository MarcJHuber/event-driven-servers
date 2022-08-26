/*
 * socket2buffer.c
 * (C)1998-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include "headers.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

void buffer2file(struct context *ctx, int cur __attribute__((unused)))
{
    ssize_t l = 0, len = 0;

    DebugIn(DEBUG_BUFFER);

    if (ctx->dbuf) {
	do {
	    struct iovec v[10];
	    int count = 10;

	    buffer_setv(ctx->dbuf, v, &count, 0);
	    l = writev(ctx->ffn, v, count);
	    if (l > 0) {
		off_t l2 = (off_t) l;
		len += l;
		ctx->dbuf = buffer_release(ctx->dbuf, &l2);
	    }
	}
	while (l > 0 && ctx->dbuf);

	if (l <= 0 && errno == EDQUOT) {
	    reply(ctx, MSG_451_Transfer_incomplete_quota);
	    logmsg("%s: quota limit reached", ctx->user);

	    ftp_log(ctx, LOG_TRANSFER, "i");
	    cleanup_file(ctx, ctx->ffn);
	    cleanup_data(ctx, ctx->dfn);
	    Debug((DEBUG_PROC, "- %s: quota exceeded\n", __func__));
	    return;
	}
	if (l < 0) {
	    if (errno != EAGAIN) {
		reply(ctx, MSG_451_Transfer_incomplete);

		ftp_log(ctx, LOG_TRANSFER, "i");
		cleanup_file(ctx, ctx->ffn);
		cleanup_data(ctx, ctx->dfn);
	    }
	    Debug((DEBUG_BUFFER, "- %s FAILURE transfer incomplete\n", __func__));
	    return;
	}
	ctx->bytecount += len;
    }
    if (ctx->dfn < 0) {		/* socket is closed */
	if (ctx->cfn < 0) {	/* control connection not available */
	    ftp_log(ctx, LOG_TRANSFER, "I");
	    cleanup_file(ctx, ctx->ffn);
	} else {
	    if (!cleanup_file(ctx, ctx->ffn)) {
		if (ctx->mode != 'z' || ctx->bytecount == 0)
		    reply(ctx, MSG_226_Transfer_complete);
		else
		    replyf(ctx, MSG_226_Transfer_completeZ, (int) (100 * ctx->filesize / ctx->bytecount), ctx->bytecount - ctx->filesize);
		ftp_log(ctx, LOG_TRANSFER, "I");
	    } else {
		ftp_log(ctx, LOG_TRANSFER, "i");
		if (errno == EDQUOT) {
		    reply(ctx, MSG_451_Transfer_incomplete_quota);
		    logmsg("%s: quota limit reached", ctx->user);
		} else
		    reply(ctx, MSG_451_Transfer_incomplete);
	    }
	    ctx->bytecount = 0;
	}
    }
    DebugOut(DEBUG_BUFFER);
}

void socket2buffer(struct context *ctx, int cur __attribute__((unused)))
{
    int thats_all = 0;
    ssize_t l;
    struct buffer *b = NULL;

    DebugIn(DEBUG_NET);

    io_sched_renew_proc(ctx->io, ctx, (void *) cleanup);

    if (ctx->dbuf == NULL)
	ctx->dbuf = buffer_get();

#ifdef WITH_ZLIB
    if (ctx->mode == 'z')
	b = buffer_get();
    else
#endif
	b = ctx->dbuf;

#ifdef WITH_SSL
    if (ctx->ssl_d)
	l = io_SSL_read(ctx->ssl_d, b->buf + b->length, b->size - b->length, ctx->io, ctx->dfn, (void *) socket2buffer);
    else
#endif
	l = read(ctx->dfn, b->buf + b->length, b->size - b->length);

    if (l > 0)
	ctx->traffic_total += l, ctx->traffic_files += l;

    thats_all = (l <= 0);

    if (!(l == -1 && errno == EAGAIN)) {
#ifdef WITH_ZLIB
	if (ctx->mode == 'z') {
	    struct buffer *out = ctx->dbuf;
	    b->length = l;
	    b->offset = 0;
	    l = 0;

	    if (!ctx->zstream) {
		ctx->zstream = Xcalloc(1, sizeof(z_stream));
		ctx->zstream->next_in = (u_char *) b->buf + b->offset;
		ctx->zstream->avail_in = b->length - b->offset;
		if (Z_OK != inflateInit(ctx->zstream)) {
		    Xfree(&ctx->zstream);

		    reply(ctx, MSG_451_Internal_error);
		    logmsg("%s: inflateInit failed", ctx->user);
		    ftp_log(ctx, LOG_TRANSFER, "i");
		    cleanup_file(ctx, ctx->ffn);
		    cleanup_data(ctx, ctx->dfn);
		    Debug((DEBUG_PROC, "- %s: inflateEnd\n", __func__));
		    return;
		}
		ctx->filesize = 0;
	    }
	    do {
		int res;
		off_t decomp;

		if (out->length == out->size) {
		    out->next = buffer_get();
		    out = out->next;
		}
		ctx->zstream->next_in = (u_char *) b->buf + b->offset;
		ctx->zstream->avail_in = b->length - b->offset;
		ctx->zstream->next_out = (u_char *) out->buf + out->length;
		ctx->zstream->avail_out = out->size - out->length;

		res = inflate(ctx->zstream, Z_NO_FLUSH);
		decomp = (char *) ctx->zstream->next_in - b->buf - b->offset;
		ctx->filesize += decomp;
		Debug((DEBUG_PROC, "inflate returns %d\n", res));
		switch (res) {
		case Z_OK:
		    Debug((DEBUG_PROC, "Z_OK\n"));
		    l += decomp;
		    b = buffer_release(b, &decomp);
		    out->length = out->size - ctx->zstream->avail_out;
		    break;
		case Z_STREAM_END:
		    Debug((DEBUG_PROC, "Z_STREAM_END\n"));
		    b = buffer_free(b);
		    ctx->dbuf->length = ctx->dbuf->size - ctx->zstream->avail_out;
		    if (Z_OK != inflateEnd(ctx->zstream)) {
			logmsg("%s: inflateEnd", ctx->user);
		      bye:
			buffer_free(b);
			Xfree(&ctx->zstream);
			reply(ctx, MSG_451_Internal_error);
			ftp_log(ctx, LOG_TRANSFER, "i");
			cleanup_file(ctx, ctx->ffn);
			cleanup_data(ctx, ctx->dfn);
			Debug((DEBUG_PROC, "- %s: inflateEnd\n", __func__));
			return;
		    }
		    Xfree(&ctx->zstream);
		    thats_all = 1;
		    break;
		default:
		    inflateEnd(ctx->zstream);
		    logmsg("%s: inflate returned %d", ctx->user, res);
		    goto bye;
		}
	    }
	    while (b);
	} else
#endif				/* WITH_ZLIB */
	{
	    if (l > 0)
		ctx->dbuf->length += l;
	    l = ctx->dbuf->length;
	}

	while (ctx->dbuf && (thats_all || (ctx->dbuf->length >= (ctx->dbuf->size >> 2) * 3))) {
	    if (l > 0 && ctx->use_ascii) {
		char lastchar = ctx->lastchar;
		char *t = (char *) ctx->dbuf->buf + ctx->dbuf->offset;
		char *u = t;
		char *ul = u + ctx->dbuf->length;

		for (; u < ul; u++)
		    if (*u == '\r') {
			lastchar = '\r';
			*t++ = '\n';
		    } else {
			if (*u != '\n' || lastchar != '\r')
			    *t++ = *u;
			lastchar = *u;
		    }

		ctx->lastchar = lastchar;
		ctx->dbuf->length = (size_t) (t - ctx->dbuf->buf);
	    }
	    if (thats_all)
		cleanup_data(ctx, ctx->dfn);
	    else
		buffer2file(ctx, ctx->ffn);

	    thats_all = 0;
	}
    }
    DebugOut(DEBUG_NET);
}

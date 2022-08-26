/*
 * buffer2socket.c
 * (C)1998-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include "headers.h"
#include <sys/uio.h>
#include "misc/mysendfile.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

static int calculate_shape(struct context *ctx)
{
/*
 * Dealing with tv_usec probably isn't worth it, as our transfer buffer is
 * far too large for handling arbitrary precision.
 */
    if (ctx->shape_bandwidth)
	ctx->tv_shape.tv_sec = ctx->transferstart - io_now.tv_sec + (time_t) (ctx->bytecount / ctx->shape_bandwidth);
    else
	ctx->tv_shape.tv_sec = 0;
    return ctx->tv_shape.tv_sec > 0;
}

static void set_out(struct context *ctx, int i __attribute__((unused)))
{
    Debug((DEBUG_PROC, "set_out(%d)\n", ctx->dfn));
    if (ctx && ctx->dfn > -1) {
	io_sched_pop(ctx->io, ctx);
	io_set_o(ctx->io, ctx->dfn);
    }
}

void buffer2socket(struct context *ctx, int cur __attribute__((unused)))
{
    ssize_t l = -1;
    struct buffer *db;

    DebugIn(DEBUG_BUFFER);

    io_sched_renew_proc(ctx->io, ctx, (void *) cleanup);

    sigbus_cur = ctx->ffn;

    ctx->buffer_filled = 0;

    if (ctx->iomode == IOMODE_read
#ifdef WITH_MMAP
	|| ctx->iomode == IOMODE_mmap
#endif				/* WITH_MMAP */
	)
	if (ctx->filename[0] && chunk_get(ctx, &ctx->io_offset)) {
	    reply(ctx, MSG_451_Internal_error);
	    cleanup_file(ctx, ctx->ffn);
	    cleanup_data(ctx, ctx->dfn);
	    Debug((DEBUG_BUFFER, "- %s: chunk_get failure\n", __func__));
	    return;
	}

    db = ctx->dbufi;

#ifdef WITH_ZLIB
    if (ctx->mode == 'z' && ctx->dbufi && !ctx->filename[0]) {
	struct buffer *out, *in;
	ctx->deflate_level = 9;
	ctx->zstream = Xcalloc(1, sizeof(z_stream));
	Debug((DEBUG_PROC, "deflate_level = %d\n", ctx->deflate_level));
	if (Z_OK != deflateInit2(ctx->zstream, ctx->deflate_level, Z_DEFLATED, 15, 8, Z_DEFAULT_STRATEGY)) {
	    deflateEnd(ctx->zstream);
	    Xfree(&ctx->zstream);
	    goto fatal;
	}
	in = ctx->dbufi;
	ctx->dbufi = NULL;
	db = ctx->dbuf = out = buffer_get();

	ctx->zstream->avail_out = out->size - out->length;

	ctx->filesize = 0;

	while (in) {
	    int len;
	    int res;

	    if (out->length == out->size || ctx->zstream->avail_out == 0) {
		out = buffer_append(out, buffer_get());
		out = out->next;
	    }

	    ctx->zstream->next_in = (u_char *) in->buf + in->offset;
	    ctx->zstream->avail_in = in->length - in->offset;

	    ctx->zstream->next_out = (u_char *) out->buf + out->length;
	    ctx->zstream->avail_out = out->size - out->length;

	    res = deflate(ctx->zstream, in->next ? Z_NO_FLUSH : Z_FINISH);
	    len = (int) ((char *) ctx->zstream->next_in - in->buf - in->offset);
	    ctx->filesize += len;
	    out->length = (char *) ctx->zstream->next_out - out->buf;
	    switch (res) {
	    case Z_OK:
		Debug((DEBUG_PROC, "Z_OK\n"));
		in = buffer_truncate(in, (off_t) len);
		break;
	    case Z_STREAM_END:
		Debug((DEBUG_PROC, "Z_STREAM_END\n"));
		in = buffer_free(in);
		deflateEnd(ctx->zstream);
		Xfree(&ctx->zstream);
		break;
	    default:
		in = buffer_free(in);
		deflateEnd(ctx->zstream);
		Xfree(&ctx->zstream);
		goto fatal;
	    }
	}
    }
#endif

    if (!ctx->dbufi && !ctx->dbuf
#ifdef WITH_SENDFILE
	&& ctx->iomode != IOMODE_sendfile
#endif				/* WITH_SENDFILE */
#ifdef WITH_ZLIB
	&& !ctx->zstream
#endif
	) {
	if (ctx->mode != 'z' || ctx->filesize == 0
#ifdef WITH_ZLIB
	    || ctx->deflate_level == 0
#endif
	    )
	    reply(ctx, MSG_226_Transfer_complete);
	else
	    replyf(ctx, MSG_226_Transfer_completeZ, (int) (100 * ctx->bytecount / ctx->filesize), ctx->filesize - ctx->bytecount);

	cleanup_file(ctx, ctx->ffn);
	cleanup_data(ctx, ctx->dfn);
	Debug((DEBUG_BUFFER, "- %s: buffer empty\n", __func__));
	return;
    } else
#ifdef WITH_SENDFILE
    if (ctx->iomode == IOMODE_sendfile) {
	size_t min;

	if (ctx->io_offset > 0) {
	    ctx->offset = lseek(ctx->ffn, ctx->io_offset, SEEK_SET);
	    ctx->remaining -= ctx->io_offset;
	    ctx->io_offset = 0;
	}

	min = (size_t) MIN(ctx->remaining, (off_t) bufsize);

	Debug((DEBUG_PROC, "sendfile (%d, %d, %lld, %lld)\n", ctx->dfn, ctx->ffn, (long long) ctx->offset, (long long) min));

	if (min > 0)
	    l = mysendfile(ctx->dfn, ctx->ffn, (off_t *) & ctx->offset, min);
	else
	    l = 0, ctx->remaining = 0;

	if (l < 0 && (!ctx->iomode_fixed || errno == EOVERFLOW)) {
#ifdef WITH_MMAP
	    if (use_mmap)
		ctx->iomode = IOMODE_mmap, ctx->iomode_fixed = 0;
	    else
#endif				/* WITH_MMAP */
		ctx->iomode = IOMODE_read, ctx->iomode_fixed = 1;
	    ctx->io_offset = ctx->offset, ctx->remaining += ctx->offset;
	    ctx->offset = 0;
	    Debug((DEBUG_BUFFER, "- %s: sendfile fallback\n", __func__));
	    return;
	}
	ctx->iomode_fixed = 1, ctx->remaining -= l;
    }				/* IOMODE_sendfile */
    else
#endif				/* WITH_SENDFILE */
#ifdef WITH_ZLIB
    if (ctx->conversion == CONV_GZ || (ctx->mode == 'z' && ctx->filename[0])) {
	struct buffer *b;
	char trailer[8];
	int res;

	int windowBits = (ctx->mode == 'z') ? 15 : -15;

	if (!ctx->zstream) {
	    acl_set_deflate_level(ctx);
	    ctx->zstream = Xcalloc(1, sizeof(z_stream));
	    if (Z_OK != deflateInit2(ctx->zstream, ctx->deflate_level, Z_DEFLATED, windowBits, 8, Z_DEFAULT_STRATEGY)) {
		deflateEnd(ctx->zstream);
		Xfree(&ctx->zstream);
		goto fatal;
	    }
	    ctx->zcrc32 = crc32(0, NULL, 0);
	    if (ctx->mode != 'z')
		ctx->dbuf = buffer_write(ctx->dbuf, "\037\213\010\0\0\0\0\0\0\03", 10);
	}

	ctx->zstream->next_in = (u_char *) ctx->chunk_start;
	ctx->zstream->avail_in = ctx->chunk_length;

	if (ctx->dbuf && ctx->dbuf->length < ctx->dbuf->size)
	    b = ctx->dbuf;
	else {
	    b = buffer_get();
	    ctx->dbuf = buffer_append(ctx->dbuf, b);
	}

	ctx->zstream->next_out = (u_char *) b->buf + b->length;
	ctx->zstream->avail_out = b->size - b->length;

	res = deflate(ctx->zstream, ctx->chunk_length ? Z_NO_FLUSH : Z_FINISH);
	switch (res) {
	case Z_OK:
	    Debug((DEBUG_BUFFER, "Z_OK\n"));
	    if (ctx->chunk_length) {
		int len = (int)
		    ((char *) ctx->zstream->next_in - ctx->chunk_start);
		if (ctx->mode != 'z')
		    ctx->zcrc32 = crc32(ctx->zcrc32, (u_char *) ctx->chunk_start, len);
		chunk_release(ctx, len);
	    }
	    b->length = (char *) ctx->zstream->next_out - b->buf;
	    break;
	case Z_STREAM_END:
	    Debug((DEBUG_BUFFER, "Z_STREAM_END\n"));
	    b->length = (char *) ctx->zstream->next_out - b->buf;
	    if (ctx->mode != 'z') {
		trailer[0] = 0xff & (ctx->zcrc32);
		trailer[1] = 0xff & (ctx->zcrc32 >> 8);
		trailer[2] = 0xff & (ctx->zcrc32 >> 16);
		trailer[3] = 0xff & (ctx->zcrc32 >> 24);
		trailer[4] = 0xff & (ctx->zstream->total_in);
		trailer[5] = 0xff & (ctx->zstream->total_in >> 8);
		trailer[6] = 0xff & (ctx->zstream->total_in >> 16);
		trailer[7] = 0xff & (ctx->zstream->total_in >> 24);
		b = buffer_write(b, trailer, 8);
	    }
	    deflateEnd(ctx->zstream);
	    Xfree(&ctx->zstream);
	    break;
	default:
	    deflateEnd(ctx->zstream);
	    Xfree(&ctx->zstream);
	    goto fatal;
	}
	db = ctx->dbuf;
    } else
#endif
    if (ctx->use_ascii && !ctx->ascii_in_buffer) {
	if (ctx->chunk_start && ctx->chunk_length > 0) {
	    char lastchar = ctx->lastchar;
	    char *t, *u = ctx->chunk_start;
	    char *tl, *ul = ctx->chunk_start + ctx->chunk_length;
	    struct buffer *buf = buffer_get();
	    ctx->dbuf = buffer_append(ctx->dbuf, buf);

	    t = buf->buf;
	    tl = t + buf->size;

	    if (ctx->chunk_length > buf->size) {
		for (; t < tl; *t++ = lastchar = *u++)
		    if (*u == '\n' && lastchar != '\r')
			*t++ = '\r';
	    } else
		for (; u < ul && t < tl; *t++ = lastchar = *u++)
		    if (*u == '\n' && lastchar != '\r')
			*t++ = '\r';

	    buf->length = (int) (t - buf->buf);

	    chunk_release(ctx, (int) (u - ctx->chunk_start));

	    ctx->lastchar = lastchar;

	    if (ctx->io_offset > 0)
		ctx->dbuf = buffer_release(ctx->dbuf, &ctx->io_offset);
	} else
	    l = 0;
	db = ctx->dbuf;
    }
    /* ascii */
    if (db) {
#ifdef WITH_SSL
	if (ctx->ssl_d) {
	    l = io_SSL_write(ctx->ssl_d, db->buf + db->offset, db->length - db->offset, ctx->io, ctx->dfn, (void *) buffer2socket);
	} else
#endif				/* WITH_SSL */
	{
	    struct iovec v[10];
	    int count = 10;
	    buffer_setv(db, v, &count, bufsize);
	    if (count)
		l = writev(ctx->dfn, v, count);
	}
    }

    if (l < 0) {
	if (errno != EAGAIN) {
#ifdef WITH_ZLIB
	  fatal:
#endif
	    if (ctx->filename[0])
		ftp_log(ctx, LOG_TRANSFER, "o");
	    reply(ctx, MSG_451_Transfer_incomplete);
	    cleanup_file(ctx, ctx->ffn);
	    cleanup_data(ctx, ctx->dfn);
	}
	Debug((DEBUG_BUFFER, "- %s: incomplete\n", __func__));
	return;
    }

    ctx->bytecount += l, ctx->traffic_total += l;
    if (ctx->filename[0])
	ctx->traffic_files += l;

    if ((ctx->use_ascii && !ctx->ascii_in_buffer)
	|| ctx->conversion == CONV_GZ || (ctx->mode == 'z')) {
	if (ctx->dbuf) {
	    off_t o = (off_t) l;
	    ctx->dbuf = buffer_release(ctx->dbuf, &o);
	}
    } else if (ctx->dbufi && ctx->mode != 'z' && ctx->conversion != CONV_GZ)
	chunk_release(ctx, l);

    if (!ctx->remaining)
	cleanup_file(ctx, ctx->ffn);

    if (!ctx->remaining && !ctx->dbufi && !ctx->dbuf
#ifdef WITH_ZLIB
	&& !ctx->zstream
#endif
	) {
	if (ctx->filename[0])
	    ftp_log(ctx, LOG_TRANSFER, "O");
	if (ctx->mode != 'z' || ctx->filesize == 0
#ifdef WITH_ZLIB
	    || ctx->deflate_level == 0
#endif
	    )
	    reply(ctx, MSG_226_Transfer_complete);
	else
	    replyf(ctx, MSG_226_Transfer_completeZ, (int) (100 * ctx->bytecount / ctx->filesize), ctx->filesize - ctx->bytecount);
	ctx->bytecount = 0;
	cleanup_data(ctx, ctx->dfn);
    } else if (calculate_shape(ctx)) {
	io_clr_o(ctx->io, ctx->dfn);
	io_sched_add(ctx->io, ctx, (void *) set_out, ctx->tv_shape.tv_sec, ctx->tv_shape.tv_usec);
    }

    DebugOut(DEBUG_BUFFER);
}

/*
 * chunk.c
 * (C)2001-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include "headers.h"
#include "misc/sysconf.h"

static const char rcsid[]
    __attribute__((used)) = "$Id$";

int chunk_get(struct context *ctx, off_t * offset)
{
    int result = 0;
    ssize_t len = 0;

    DebugIn(DEBUG_BUFFER);

    Debug((DEBUG_PROC, "remaining is %lu\n", (long unsigned) ctx->remaining));
    if (ctx->remaining && bufsize > buffer_getlen(ctx->dbufi)) {
#ifdef WITH_MMAP
	if (ctx->iomode == IOMODE_mmap) {
	    struct buffer *b = buffer_get_mmap();
	    if (offset && *offset) {
		ctx->offset = pagesize * (*offset / pagesize);
		b->offset = (size_t) (*offset - ctx->offset);
		ctx->remaining -= *offset;
	    }
	    if (bufsize_mmap)
		b->length = (size_t) (MIN((off_t) b->offset + ctx->remaining, (off_t) bufsize_mmap));
	    else
		b->length = (size_t) (b->offset + (off_t) ctx->remaining);

	    b->size = b->length;

	    b->buf = (char *) mmap(0, b->length, PROT_READ, MAP_SHARED, ctx->ffn, ctx->offset);

	    if (b->buf == MAP_FAILED) {
		if (offset && *offset) {
		    ctx->remaining += ctx->offset;
		    ctx->offset = 0;
		}
		if (ctx->iomode_fixed) {
		    logerr("mmap (%s:%d): %s", __FILE__, __LINE__, ctx->filename);
		    ctx->remaining = 0, len = 0, result = -1;
		} else {
		    ctx->iomode = IOMODE_read, ctx->iomode_fixed = 1;
		    buffer_free_all(b);
		}
	    } else {
		if (offset)
		    *offset = 0;
		ctx->iomode_fixed = 1;
		ctx->dbufi = buffer_append(ctx->dbufi, b);
		madvise(b->buf, b->length, MADV_SEQUENTIAL);
		ctx->remaining -= b->length - b->offset, ctx->offset += b->length;
		if (!ctx->dbufi || ctx->dbufi->length == 0)
		    result = -1;
	    }
	}
#endif				/* WITH_MMAP */
	if (ctx->iomode == IOMODE_read) {
	    struct buffer *buf = buffer_get();
	    if (offset && *offset) {
		ctx->offset = lseek(ctx->ffn, *offset, SEEK_SET);
		ctx->remaining -= *offset;
		*offset = 0;
	    }
	    len = read(ctx->ffn, buf->buf, (size_t) MIN(ctx->remaining, (off_t) buf->size));
	    if (len <= 0) {
		if (len < 0)
		    logerr("read (%s:%d): %s", __FILE__, __LINE__, ctx->filename);
		ctx->remaining = 0, result = -1;
		buffer_free(buf);
	    } else {
		ctx->remaining -= len, ctx->offset += len, buf->length = len;
		ctx->dbufi = buffer_append(ctx->dbufi, buf);
	    }
	}
    }
    if (ctx->dbufi) {
	ctx->chunk_start = ctx->dbufi->buf + ctx->dbufi->offset;
	ctx->chunk_length = ctx->dbufi->length - ctx->dbufi->offset;
    } else {
	ctx->chunk_start = NULL;
	ctx->chunk_length = 0;
    }
    DebugOut(DEBUG_BUFFER);
    return result;
}

int chunk_release(struct context *ctx, off_t len)
{
    DebugIn(DEBUG_BUFFER);

    ctx->dbufi = buffer_release(ctx->dbufi, &len);
    if (ctx->dbufi) {
	ctx->chunk_start = ctx->dbufi->buf + ctx->dbufi->offset;
	ctx->chunk_length = ctx->dbufi->length - ctx->dbufi->offset;
    } else {
	ctx->chunk_start = NULL;
	ctx->chunk_length = 0;
    }
    DebugOut(DEBUG_BUFFER);
    return 0;
}

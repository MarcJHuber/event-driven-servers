/*
 * file2buffer.c
 * (C)1998-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include "headers.h"
#include "misc/tohex.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

/*
 * This code is somewhat similar to the one found in h_site_checksum.c,
 * but not compatible enough to be merged.
 */

void file2buffer(struct context *ctx, int cur __attribute__((unused)))
{
    ssize_t len = 0;
    DebugIn(DEBUG_BUFFER);

    sigbus_cur = ctx->cfn;

    if (chunk_get(ctx, NULL)) {
	cleanup_file(ctx, ctx->ffn);
	cleanup_data(ctx, ctx->dfn);
	io_sched_pop(ctx->io, ctx);
	ctx->iomode = IOMODE_dunno;
	ctx->chunk_start = NULL;
	ctx->chunk_length = 0;
	ctx->buffer_filled = 0;
	reply(ctx, MSG_451_Transfer_incomplete);
    } else {
	if (chunk_remaining(ctx)) {
	    len = MIN(ctx->chunk_length, (size_t) bufsize);
	    if (ctx->conversion == CONV_CRC)
		ctx->checksum.crc32 = crc32_update(ctx->checksum.crc32, (u_char *) ctx->chunk_start, len);
	    else
		myMD5Update(&ctx->checksum.md5context, (u_char *) ctx->chunk_start, len);
	    chunk_release(ctx, len);
	}

	if (chunk_remaining(ctx))
	    io_sched_renew_proc(ctx->io, ctx, (void *) file2buffer);
	else {
	    ctx->dbuf = buffer_free_all(ctx->dbuf);
	    ctx->dbufi = buffer_free_all(ctx->dbufi);
	    ctx->dbufi = buffer_get();
	    io_sched_pop(ctx->io, ctx);
	    ctx->iomode = IOMODE_dunno;
	    if (ctx->conversion == CONV_CRC)
		ctx->dbufi->length =
		    snprintf(ctx->dbufi->buf, ctx->dbufi->size,
			     "%u %llu %s\n", crc32_final(ctx->checksum.crc32, ctx->offset), (unsigned long long) ctx->offset, ctx->filename + ctx->rootlen);
	    else {
		char digest[16], d[33];
		myMD5Final((u_char *) digest, &ctx->checksum.md5context);
		tohex((u_char *) digest, 16, d);
		ctx->dbufi->length = snprintf(ctx->dbufi->buf, ctx->dbufi->size, "%s  %s\n", d, ctx->filename + ctx->rootlen);
	    }
	    ctx->offset = 0, ctx->remaining = 0, ctx->conversion = CONV_NONE;
	    if (ctx->dfn > -1 && io_get_cb_o(ctx->io, ctx->dfn) == (void *) buffer2socket)
		io_set_o(ctx->io, ctx->dfn);
	    cleanup_file(ctx, ctx->ffn);
	    ctx->chunk_start = ctx->dbufi->buf;
	    ctx->chunk_length = ctx->dbufi->length;
	    ctx->buffer_filled = 1;
	}
    }
    DebugOut(DEBUG_BUFFER);
}

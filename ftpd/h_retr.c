/*
 * h_retr.c
 *
 * (C)1998-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include "headers.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

void h_retr(struct context *ctx, char *arg)
{
    char *t;
    int f = -1, st1 = -1, st2 = -1;
    struct stat st;

    DebugIn(DEBUG_COMMAND);

    if (ctx->transfer_in_progress) {
	reply(ctx, MSG_501_Transfer_in_progress);
	DebugOut(DEBUG_COMMAND);
	return;
    }

    ctx->outgoing_data = 1;
    if (ctx->dfn > -1 && io_get_cb_i(ctx->io, ctx->dfn) == (void *) accept_data) {
	io_set_i(ctx->io, ctx->dfn);
	io_clr_o(ctx->io, ctx->dfn);
	io_set_cb_e(ctx->io, ctx->dfn, (void *) cleanup_data);
	io_set_cb_h(ctx->io, ctx->dfn, (void *) cleanup_data);
    }

    ctx->quota_update_on_close = 0;

    ctx->conversion = CONV_NONE;

    if ((t = buildpath(ctx, arg))) {
	st1 = pickystat(ctx, &st, t);
	if (st1)
	    st2 = convstat(ctx, &st, t);
    }

    if (!st2 && acl_binary_only(ctx, arg, t)) {
	reply(ctx, MSG_504_no_ascii);
	cleanup_data_reuse(ctx, ctx->dfn);
    } else if ((st1 && !st2) && ((ctx->conversion == CONV_GZ && acl_compression(ctx, arg, t))
				 || (ctx->conversion == CONV_MD5 && acl_checksum(ctx, arg, t))
				 || (ctx->conversion == CONV_CRC && acl_checksum(ctx, arg, t)))) {
	cleanup_data_reuse(ctx, ctx->dfn);
	reply(ctx, MSG_550_No_such_file);
    } else if ((!st1 || !st2) && S_ISREG(st.st_mode) && ((f = open(t, O_RDONLY | O_LARGEFILE)) > -1)) {
	fcntl(f, F_SETFD, FD_CLOEXEC);

	if (ctx->dfn < 0)
	    connect_port(ctx);

	if (ctx->dfn < 0) {
	    reply(ctx, MSG_431_Opening_datacon_failed);
	    ctx->dbuf = buffer_free_all(ctx->dbuf);
	    close(f);
	    DebugOut(DEBUG_COMMAND);
	    return;
	}

	Debug((DEBUG_PROC, " file fd: %d data fd: %d\n", f, ctx->dfn));

	if (ctx->conversion == CONV_MD5 || ctx->conversion == CONV_CRC) {
//          ctx->io_offset = 0;
	    io_sched_add(ctx->io, ctx, (void *) file2buffer, 0, 0);
	}
	ctx->ffn = f;

	if (strlen(t) >= sizeof(ctx->filename)) {
	    logerr("buffer too small in %s:%d (%s/%s)", __FILE__, __LINE__, ctx->user, t);
	    reply(ctx, MSG_551_Internal_error);
	    cleanup_data_reuse(ctx, ctx->dfn);
	    DebugOut(DEBUG_COMMAND);
	    return;
	}
	strcpy(ctx->filename, t);
	ctx->filesize = st.st_size;
	ctx->remaining = st.st_size;
	if ((ctx->io_offset_end != -1)
	    && (ctx->remaining > ctx->io_offset_end + 1))
	    ctx->remaining = ctx->io_offset_end + 1;
	ctx->offset = 0;
	ctx->bytecount = 0;
	ctx->count_files++;
	ctx->iomode_fixed = 0;
#ifdef WITH_SENDFILE
	if (!ctx->use_tls_d && use_sendfile && !ctx->use_ascii && ctx->conversion == CONV_NONE && ctx->mode != 'z')
	    ctx->iomode = IOMODE_sendfile;
	else
#endif				/* WITH_SENDFILE */
#ifdef WITH_MMAP
	if (use_mmap)
	    ctx->iomode = IOMODE_mmap;
	else
#endif				/* WITH_MMAP */
	    ctx->iomode = IOMODE_read, ctx->iomode_fixed = 1;

	if (io_get_cb_o(ctx->io, ctx->dfn) == (void *) buffer2socket) {
	    /* already connected */
	    if (ctx->conversion == CONV_MD5 || ctx->conversion == CONV_CRC)
		io_clr_o(ctx->io, ctx->dfn);
	    else
		io_set_o(ctx->io, ctx->dfn);

	    io_clr_i(ctx->io, ctx->dfn);
	}

	if (io_get_cb_o(ctx->io, ctx->dfn) == (void *) buffer2socket || is_connected(ctx->dfn)) {
	    /*
	     * For ASCII and on-the-fly conversions we don't know transfer sizes.
	     */
	    if (ctx->use_ascii)
		replyf(ctx, MSG_125_Starting_dc, "ASCII", ctx->use_tls_d ? "TLS " : "");
	    else if (ctx->conversion == CONV_NONE)
		replyf(ctx, MSG_125_Starting_dc_bytes,
		       ctx->use_tls_d ? "TLS " : "", (unsigned long long) ctx->remaining - (unsigned long long) ctx->io_offset);
	    else
		replyf(ctx, MSG_125_Starting_dc, "Binary", ctx->use_tls_d ? "TLS " : "");
	} else {
	    if (ctx->use_ascii)
		replyf(ctx, MSG_150_Opening_dc, "ASCII", ctx->use_tls_d ? "TLS " : "");
	    else if (ctx->conversion == CONV_NONE && ctx->mode != 'z')
		replyf(ctx, MSG_150_Opening_dc_bytes,
		       ctx->use_tls_d ? "TLS " : "", (unsigned long long) ctx->remaining - (unsigned long long) ctx->io_offset);
	    else
		replyf(ctx, MSG_150_Opening_dc, "binary", ctx->use_tls_d ? "TLS " : "");
	}
	ctx->transfer_in_progress = 1;
	ctx->transferstart = io_now.tv_sec;
    } else {
	if (f > -1)
	    close(f);
	reply(ctx, MSG_550_No_such_file);

	cleanup_data_reuse(ctx, ctx->dfn);
    }

    DebugOut(DEBUG_COMMAND);
}

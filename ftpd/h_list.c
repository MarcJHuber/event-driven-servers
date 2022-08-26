/*
 * h_list.c
 * (C)1998-2011 by Marc Huber <Marc.Huber@web.de>
 *
 * $Id$
 *
 */

#include "headers.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

static void xlist_done(struct context *ctx, int);

static void xlist(struct context *ctx, char *arg, enum list_mode mode)
{
    DebugIn(DEBUG_COMMAND);

    if (ctx->transfer_in_progress)
	reply(ctx, MSG_501_Transfer_in_progress);
    else {
	ctx->transfer_in_progress = 1;
	ctx->conversion = CONV_NONE;
	ctx->filename[0] = 0;
	ctx->io_offset = 0;
	ctx->bytecount = 0;
	ctx->filesize = 0;
	ctx->outgoing_data = 1;
	ctx->ascii_in_buffer = 1;

	io_sched_add(ctx->io, ctx, (void *) xlist_done, (time_t) 0, (suseconds_t) 0);
	list(ctx, arg, mode);
    }
    DebugOut(DEBUG_COMMAND);
}

static void xlist_done(struct context *ctx, int cur __attribute__((unused)))
{
    DebugIn(DEBUG_COMMAND);

    io_sched_pop(ctx->io, ctx);

    if (!ctx->dbufi && ctx->list_mode == List_mlsd) {
	reply(ctx, MSG_501_No_such_dir);
	if (ctx->dfn > -1)
	    cleanup_data_reuse(ctx, ctx->dfn);
	DebugOut(DEBUG_COMMAND);
	return;
    }

    if (ctx->dfn < 0) {
	connect_port(ctx);
	if (ctx->dfn < 0) {
	    reply(ctx, MSG_431_Opening_datacon_failed);
	    buffer_free_all(ctx->dbuf);
	    ctx->dbuf = NULL;
	    DebugOut(DEBUG_COMMAND);
	    return;
	}
    }

    if (io_get_cb_i(ctx->io, ctx->dfn) == (void *) accept_data) {
	io_set_i(ctx->io, ctx->dfn);
	io_clr_o(ctx->io, ctx->dfn);
	io_set_cb_e(ctx->io, ctx->dfn, (void *) cleanup_data);
	io_set_cb_h(ctx->io, ctx->dfn, (void *) cleanup_data);
    }

    if (io_get_cb_o(ctx->io, ctx->dfn) == (void *) buffer2socket) {
	/* already connected */
	io_clr_cb_i(ctx->io, ctx->dfn);
	io_clr_i(ctx->io, ctx->dfn);
	io_set_o(ctx->io, ctx->dfn);
    }

    if (io_get_cb_o(ctx->io, ctx->dfn) == (void *) buffer2socket || is_connected(ctx->dfn))
	replyf(ctx, MSG_125_Starting_dc, "ASCII", ctx->use_tls_d ? "TLS " : "");
    else
	replyf(ctx, MSG_150_Opening_dc, "ASCII", ctx->use_tls_d ? "TLS " : "");

    DebugOut(DEBUG_COMMAND);
}

void h_list(struct context *ctx, char *arg)
{
    DebugIn(DEBUG_COMMAND);
    xlist(ctx, arg, List_list);
    DebugOut(DEBUG_COMMAND);
}

void h_nlst(struct context *ctx, char *arg)
{
    DebugIn(DEBUG_COMMAND);
    xlist(ctx, arg, List_nlst);
    DebugOut(DEBUG_COMMAND);
}

void h_mlsd(struct context *ctx, char *arg)
{
    DebugIn(DEBUG_COMMAND);
    xlist(ctx, arg, List_mlsd);
    DebugOut(DEBUG_COMMAND);
}

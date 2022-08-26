/*
 * cleanup.c
 * (C)1997-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include "headers.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

static void cleanup_context(struct context *, int);

static void cleanup_control_finish(struct context *ctx, int cur)
{
    Debug((DEBUG_PROC, "cleanup_control_finish\n"));
    io_close(ctx->io, cur);
    ctx->cfn = -1;

    if (ctx->sctp_fn > -1) {
	close(ctx->sctp_fn);
	ctx->sctp_fn = -1;
    }

    cleanup_context(ctx, -1);
}

void cleanup_control_ssl_error(struct context *ctx, int cur)
{
#ifdef WITH_SSL
    if (ctx->ssl_c) {
	SSL_free(ctx->ssl_c);
	ctx->ssl_c = NULL;
    }
#endif
    cleanup_control(ctx, cur);
}

void cleanup_data_ssl_error(struct context *ctx, int cur)
{
#ifdef WITH_SSL
    if (ctx->ssl_d) {
	SSL_free(ctx->ssl_d);
	ctx->ssl_d = NULL;
    }
#endif
    cleanup_data(ctx, cur);
}

static void cleanup_data_finish(struct context *ctx, int cur __attribute__((unused)))
{
    DebugIn(DEBUG_PROC | DEBUG_NET);
    if (ctx->dfn > -1) {
	io_close(ctx->io, ctx->dfn);
	ctx->dfn = -1;
	ctx->buffer_filled = 0;
	ctx->ascii_in_buffer = 0;
	ctx->conversion = CONV_NONE;
	cleanup_context(ctx, -1);
    }
    DebugOut(DEBUG_PROC | DEBUG_NET);
}

#ifdef WITH_SSL
static void ssl_cleanup_control(struct context *ctx, int cur __attribute__((unused)))
{
    Debug((DEBUG_PROC, "ssl_cleanup_control\n"));

    if (io_SSL_shutdown(ctx->ssl_c, ctx->io, ctx->cfn, (void *) ssl_cleanup_control) < 0 && errno == EAGAIN)
	return;

    SSL_free(ctx->ssl_c);
    ctx->ssl_c = NULL;
    cleanup_control_finish(ctx, ctx->cfn);
}

static void ssl_cleanup_data(struct context *ctx, int cur __attribute__((unused)))
{
    Debug((DEBUG_PROC, "ssl_cleanup_data\n"));

    if (io_SSL_shutdown(ctx->ssl_d, ctx->io, ctx->dfn, (void *) ssl_cleanup_data) < 0 && errno == EAGAIN)
	return;

    SSL_free(ctx->ssl_d);
    ctx->ssl_d = NULL;
    cleanup_data_finish(ctx, ctx->dfn);
}
#endif				/* WITH_SSL */

void cleanup_ident(struct context *ctx, int cur __attribute__((unused)))
{
    DebugIn(DEBUG_PROC);

    if (ctx->ifn > -1) {
	io_clr_i(ctx->io, ctx->ifn);
	io_clr_o(ctx->io, ctx->ifn);

	io_close(ctx->io, ctx->ifn);
	Xfree(&ctx->ident_buf);
	ctx->ifn = -1;
    }

    DebugOut(DEBUG_PROC);
}

void cleanup_control(struct context *ctx, int cur __attribute__((unused)))
{
    DebugIn(DEBUG_PROC);

    if (ctx->cfn > -1) {
#ifdef WITH_SSL
	if (io_get_cb_i(ctx->io, ctx->cfn) == (void *) ssl_cleanup_control) {
	    Debug((DEBUG_PROC, "- %s #C\n", __func__));
	    return;
	}
#endif

	ftp_log(ctx, LOG_EVENT, ctx->login_logged ? "logout" : "reject");

	if (ctx->ffn < 0 && ctx->dbuf)
	    cleanup_data(ctx, ctx->dfn);

#ifdef WITH_SSL
	if (ctx->ssl_c) {
	    io_clr_i(ctx->io, ctx->cfn);
	    io_clr_o(ctx->io, ctx->cfn);
	    ssl_cleanup_control(ctx, ctx->cfn);
	} else
#endif				/* WITH_SSL */
	    cleanup_control_finish(ctx, ctx->cfn);
    }
    DebugOut(DEBUG_PROC);
}

void cleanup_data_reuse(struct context *ctx, int cur __attribute__((unused)))
{
    if (ctx->dfn > -1) {
	ctx->outgoing_data = 0;
	io_clr_o(ctx->io, ctx->dfn);
	io_clr_i(ctx->io, ctx->dfn);

	if (io_get_cb_o(ctx->io, ctx->dfn) == (void *) buffer2socket)
	    io_set_cb_i(ctx->io, ctx->dfn, (void *) socket2buffer);
	else if (io_get_cb_i(ctx->io, ctx->dfn) == (void *) socket2buffer)
	    io_set_cb_o(ctx->io, ctx->dfn, (void *) buffer2socket);
    }
    ctx->estp = 0;
    ctx->estp_valid = 0;
    ctx->passive_transfer = 0;
    ctx->transfer_in_progress = 0;
}

void cleanup_data(struct context *ctx, int cur __attribute__((unused)))
{
    int ffn = ctx->ffn;
    int outgoing_data = ctx->outgoing_data;

    DebugIn(DEBUG_PROC | DEBUG_NET);

    ctx->estp = 0;
    ctx->estp_valid = 0;
    ctx->passive_transfer = 0;
    ctx->transfer_in_progress = 0;

    if (ctx->dfn > -1) {
	ctx->iomode = IOMODE_dunno, ctx->iomode_fixed = 0;
#ifdef WITH_SSL
	if (io_get_cb_i(ctx->io, ctx->dfn) == (void *) ssl_cleanup_data) {
	    Debug((DEBUG_PROC, "- %s #C\n", __func__));
	    return;
	}
#endif

	if (io_sched_del(ctx->io, ctx, (void *) cleanup_data)) {
	    if (io_get_cb_i(ctx->io, ctx->dfn) == (void *) connect_data)
		reply(ctx, MSG_431_Opening_datacon_failed);
	    ctx->dbufi = buffer_free_all(ctx->dbufi);
	    if (ctx->ffn < 0 || io_get_cb_i(ctx->io, ctx->dfn) != (void *) socket2buffer) {
		ctx->dbuf = buffer_free_all(ctx->dbuf);
		if (ctx->ffn > -1)
		    cleanup_file(ctx, ctx->ffn);
	    }
	}

	Debug((DEBUG_PROC | DEBUG_NET, "  ctx->dfn: %d\n", ctx->dfn));

	io_clr_cb_i(ctx->io, ctx->dfn);
	io_clr_cb_o(ctx->io, ctx->dfn);

	if (ctx->ffn < 0 || outgoing_data) {
	    ctx->dbuf = buffer_free_all(ctx->dbuf);
	    ctx->dbufi = buffer_free_all(ctx->dbufi);
	}

	/* reset remote data CEP to defaults */
	ctx->sa_d_remote = ctx->sa_c_remote;

#ifdef WITH_SSL
	if (ctx->ssl_d) {
	    io_clr_i(ctx->io, ctx->dfn);
	    io_clr_o(ctx->io, ctx->dfn);
	    ssl_cleanup_data(ctx, ctx->dfn);
	} else
#endif				/* WITH_SSL */
	    cleanup_data_finish(ctx, ctx->dfn);
    }
    if (ffn > -1) {
	if (outgoing_data)
	    cleanup_file(ctx, ffn);
	else
	    buffer2file(ctx, ffn);
    }

    DebugOut(DEBUG_PROC | DEBUG_NET);
}

int cleanup_file(struct context *ctx, int cur __attribute__((unused)))
{
    int result = 0;

    DebugIn(DEBUG_PROC);

    if (ctx->ffn > -1) {
	Debug((DEBUG_PROC, "  ctx->ffn: %d\n", ctx->ffn));

	ctx->io_offset = 0;
	ctx->io_offset_start = 0;
	ctx->io_offset_end = -1;

	if (ctx->quota_path && ctx->quota_update_on_close) {
	    struct stat st;
	    fstat(ctx->ffn, &st);
	    quota_add(ctx, st.st_size - ctx->quota_filesize_before_stor);
	}

	result = close(ctx->ffn);

	ctx->ffn = -1;
	cleanup_context(ctx, -1);
    }

    DebugOut(DEBUG_PROC);

    return result;
}

static void cleanup_context(struct context *ctx, int cur __attribute__((unused)))
{
    DebugIn(DEBUG_PROC);

    if (ctx->ffn > -1 || ctx->dfn > -1 || ctx->cfn > -1) {
	Debug((DEBUG_PROC, "- %s (not yet)\n", __func__));
	return;
    }

    if (ctx->is_client) {
	struct scm_data sd;
	sd.type = SCM_DONE;
	if (common_data.scm_send_msg(0, &sd, -1))
	    die_when_idle = -1;

	common_data.users_cur--;
	if (common_data.users_cur == 0 && die_when_idle) {
	    Debug((DEBUG_PROC, "exiting -- process out of use\n"));
	    mavis_drop(mcx);
	    logmsg("Terminating, no longer needed.");
	    exit(EX_OK);
	}
    }

    if (ctx->ifn > -1)
	cleanup_ident(ctx, ctx->ifn);

#ifdef WITH_LWRES
    if (ctx->reverse)
	Xfree(&ctx->reverse);
    else
	io_dns_cancel(idc, ctx);
#endif				/* WITH_LWRES */

#ifdef WITH_SSL
    Xfree(&ctx->certsubj);
    Xfree(&ctx->certsubjaltname);
#endif

    ctx->pst_valid = 0;

    Xfree(&ctx->ident_buf);
    Xfree(&ctx->ident_user);
    Xfree(&ctx->user);
    Xfree(&ctx->email);
    Xfree(&ctx->vhost);
    Xfree(&ctx->visited_dirs);
    if (ctx->auth_in_progress)
	mavis_cancel(mcx, ctx);

#ifdef WITH_ZLIB
    if (ctx->zstream) {
	deflateEnd(ctx->zstream);
	Xfree(&ctx->zstream);
    }
#endif

    RB_tree_delete(ctx->filelist);

    while (io_sched_pop(ctx->io, ctx));

    if (ctx->dirfn > -1)
	close(ctx->dirfn);

    if (ctx->incoming) {
	regfree(ctx->incoming);
	free(ctx->incoming);
    }

    Xfree(&ctx->quota_path);

    buffer_free_all(ctx->cbufi);
    buffer_free_all(ctx->cbufo);
    buffer_free_all(ctx->dbuf);
    buffer_free_all(ctx->dbufi);
    free(ctx);

    set_proctitle(die_when_idle ? ACCEPT_NEVER : ACCEPT_YES);

    DebugOut(DEBUG_PROC);
}

void cleanup(struct context *ctx, int cur __attribute__((unused)))
{
    struct io_context *io = ctx->io;
    int cfn = ctx->cfn;
    int dfn = ctx->dfn;
    int ffn = ctx->ffn;

    Debug((DEBUG_PROC, "+ %s(%d)\n", __func__, cur));

    while (io_sched_pop(ctx->io, ctx));

    if (dfn > -1 && io_get_ctx(io, dfn))
	cleanup_data(ctx, dfn);
    if (ffn > -1 && io_get_ctx(io, ffn))
	cleanup_file(ctx, ffn);
    if (cfn > -1 && io_get_ctx(io, cfn))
	cleanup_control(ctx, cfn);

    DebugOut(DEBUG_PROC);
}

void cleanup_spawnd(struct context *ctx __attribute__((unused)), int cur __attribute__((unused)))
{
    if (common_data.users_cur == 0) {
	Debug((DEBUG_PROC, "exiting -- process out of use\n"));
	mavis_drop(mcx);
	logmsg("Terminating, no longer needed.");
	exit(EX_OK);
    }
    die_when_idle = -1;
    set_proctitle(ACCEPT_NEVER);
}

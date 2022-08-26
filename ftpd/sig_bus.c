/*
 * sig_bus.c
 * (C)2001-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include "misc/sysconf.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

#include "headers.h"

static void catchbus(int sig __attribute__((unused)))
{
    struct context *ctx;
    if (sigbus_cur > -1 && (ctx = io_get_ctx(ctx_spawnd->io, sigbus_cur))) {
	logmsg("catched SIGBUS (%s)", ctx->filename);
	ctx->dbuf = buffer_free_all(ctx->dbuf);
	ctx->dbufi = buffer_free_all(ctx->dbufi);
	ctx->chunk_start = NULL;
	ctx->chunk_length = 0;
	ctx->remaining = 0;
	cleanup_file(ctx, sigbus_cur);
	if (ctx->dfn > -1) {
	    reply(ctx, MSG_451_Transfer_incomplete);
	    cleanup_data(ctx, ctx->dfn);
	}
    }
    signal(SIGBUS, catchbus);
    longjmp(sigbus_jmpbuf, 1);
}

void setup_sig_bus()
{
    signal(SIGBUS, catchbus);
}

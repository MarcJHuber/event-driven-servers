/*
 * readcmd.c
 * (C)1997-2011 Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 * 
 * $Id$
 *
 */

/*
 * Standards compliance: We're ignoring the Telnet SYNCH/IP signals,
 * but this really shouldn't matter as the daemon is perfectly capable
 * of monitoring the control connection while transfering data.
 */

#include "headers.h"
#include <arpa/telnet.h>

static const char rcsid[] __attribute__((used)) = "$Id$";

static void parsecmd(struct context *, int);

void readcmd(struct context *ctx, int cur __attribute__((unused)))
{
    int iac_state;
    ssize_t i;
    char *t, *u;
    struct buffer *b = ctx->cbufi;

    Debug((DEBUG_PROC, "+ %s(%d)\n", __func__, ctx->cfn));

    io_clr_i(ctx->io, ctx->cfn);

    if (b) {
	while (b->next)
	    b = b->next;
	if (b->size == b->length) {
	    b->next = buffer_get();
	    b = b->next;
	}
    } else
	ctx->cbufi = b = buffer_get();

#ifdef WITH_SSL
    if (ctx->ssl_c)
	i = io_SSL_read(ctx->ssl_c, b->buf + b->length, b->size - b->length, ctx->io, ctx->cfn, (void *) readcmd);
    else
#endif
	i = read(ctx->cfn, b->buf + b->length, b->size - b->length);

    if (i <= 0) {
	if (i != -1 || errno != EAGAIN)
	    cleanup(ctx, ctx->cfn);

	Debug((DEBUG_PROC, "- %s (<= 0)\n", __func__));
	return;
    }

    b->offset = b->length;
    b->length += i, ctx->traffic_total += i;

    /* First, process telnet options */

    iac_state = ctx->iac_state;

    t = u = b->buf + b->offset;
    for (; i; i--, t++)
	switch (iac_state) {
	case 0:
	    switch (*t & 0377) {
	    case IAC:
		iac_state = 1;
		break;
	    default:
		*u++ = *t;
	    }
	    break;
	case 1:
	    switch (*t & 0377) {
	    case IAC:
		iac_state = 0;
		*u++ = 0xff /* IAC */;
		break;
	    case WILL:
	    case WONT:
		ctx->iac[1] = DONT;
		iac_state = 2;
		break;
	    case DO:
	    case DONT:
		ctx->iac[1] = WONT;
		iac_state = 2;
		break;
	    default:
		iac_state = 0;
	    }
	    break;
	case 2:
	    ctx->iac[2] = *t;
	    iac_state = 0;
	    ctx->cbufo = buffer_write(ctx->cbufo, (char *) ctx->iac, 3);
	    io_set_o(ctx->io, ctx->cfn);
	}

    ctx->iac_state = iac_state;

    b->length = u - b->buf;

    parsecmd(ctx, ctx->cfn);

    DebugOut(DEBUG_PROC);
}

static void parsecmd(struct context *ctx, int cfn)
{
    char *t, *u;
    char lastchar = 0;		/* Anything different from <CR> will do. */
    DebugIn(DEBUG_PROC);

    t = u = ctx->cbufi->buf + ctx->cbufi->offset;

  again:

    for (; t < ctx->cbufi->buf + ctx->cbufi->length; t++)
	switch (*t) {
	case '\0':
	    if (lastchar == '\r')	/* <CR><NUL> => <CR> */
		lastchar = *u++ = *t;
	    else {
		Debug((DEBUG_PROC, " %s: Illegal character sequence \\%o\\%o\n", __func__, lastchar, *t));
		cleanup(ctx, ctx->cfn);
		DebugOut(DEBUG_PROC);
		return;
	    }
	    break;
	case '\n':
	    if (lastchar == '\r') {	/* <CR><LF> => EOL */
		struct io_context *io = ctx->io;
		cfn = ctx->cfn;
		*(u - 1) = 0;
		checkcmd(ctx, ctx->cbufi->buf);

		if (io_get_ctx(io, cfn))
		    /* need to check whether our context is still valid */
		{
		    ctx->cbufi->offset = t - ctx->cbufi->buf + 1;
		    if (ctx->cbufi->offset == ctx->cbufi->length) {
			ctx->cbufi = buffer_free(ctx->cbufi);
			io_sched_del(ctx->io, ctx, (void *) parsecmd);
			if (!ctx->cbufi && io_get_cb_i(ctx->io, ctx->cfn) == (void *) readcmd)
			    io_set_i(ctx->io, ctx->cfn);
		    } else if (io_sched_renew_proc(ctx->io, ctx, (void *) parsecmd))
			io_sched_add(ctx->io, ctx, (void *) parsecmd, 0, 0);
		}
		DebugOut(DEBUG_PROC);
		return;
	    }
	default:
	    lastchar = *u++ = *t;
	}

    /*
     * The FTP protocol doesn't support pipelining. No way this code can
     * be reached with a well-behaving client.
     */

    /*
     * Move content of input buffer to beginning of buffer.
     */
    if (ctx->cbufi->offset != ctx->cbufi->length) {
	ctx->cbufi->length -= ctx->cbufi->offset;
	memmove(ctx->cbufi->buf, ctx->cbufi->buf + ctx->cbufi->offset, ctx->cbufi->length);
	t -= ctx->cbufi->offset, u -= ctx->cbufi->offset;
	ctx->cbufi->offset = 0;
    }

    /*
     * If we have more data, try to fill current buffer, then continue parsing.
     */
    if (ctx->cbufi->next && ctx->cbufi->length < ctx->cbufi->size) {
	size_t len = MIN(ctx->cbufi->size - ctx->cbufi->length,
			 ctx->cbufi->next->length - ctx->cbufi->offset);
	memcpy(ctx->cbufi->buf + ctx->cbufi->length, ctx->cbufi->next->buf + ctx->cbufi->offset, len);
	ctx->cbufi->length += len, ctx->cbufi->next->offset += len;
	if (ctx->cbufi->next->offset == ctx->cbufi->next->length)
	    ctx->cbufi->next = buffer_free(ctx->cbufi->next);
	goto again;
    }

    /*
     * Terminate connection if buffer filled but no <CR><LF> is found.
     * Otherwise, accept more input.
     */
    if (ctx->cbufi->length == ctx->cbufi->size) {
	logmsg("Found garbage in command buffer. Terminating session %.8lx", ctx->id);
	cleanup(ctx, ctx->cfn);
    } else
	io_set_i(ctx->io, ctx->cfn);

    DebugOut(DEBUG_PROC);
}

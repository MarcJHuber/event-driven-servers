/*
 * h_stat.c
 *
 * (C)1998-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include "headers.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

static void stat_list_done(struct context *ctx)
{
    DebugIn(DEBUG_COMMAND);
    io_sched_pop(ctx->io, ctx);
    reply(ctx, ctx->stat_reply);
    DebugOut(DEBUG_COMMAND);
}

void h_stat(struct context *ctx, char *arg)
{
    DebugIn(DEBUG_COMMAND);

    if ((ctx->state == ST_pass) && arg && *arg) {
	io_sched_add(ctx->io, ctx, (void *) stat_list_done, 0, 0);
	list_stat(ctx, arg);
    } else {
	reply(ctx, MSG_211_Server_status);
	replyf(ctx, MSG_Transfer_type, ctx->use_ascii ? "ASCII" : "BINARY");
#ifdef WITH_ZLIB
	replyf(ctx, MSG_Transfer_mode, ctx->mode == 'Z' ? "DEFLATE" : "STREAM");
#endif

#ifdef WITH_SSL
	reply(ctx, MSG_Protection_control);
	if (ctx->ssl_c)
	    replyf(ctx, MSG_protected_cipher, SSL_get_cipher(ctx->ssl_c), SSL_get_cipher_bits(ctx->ssl_c, NULL), SSL_get_cipher_version(ctx->ssl_c));
	else
	    reply(ctx, MSG_unprotected);

	reply(ctx, MSG_Protection_data);
	if (ctx->use_tls_d) {
	    if (ctx->ssl_d) {
		const char *ci = SSL_get_cipher(ctx->ssl_d);
		int bi = SSL_get_cipher_bits(ctx->ssl_d, NULL);
		const char *ve = SSL_get_cipher_version(ctx->ssl_d);

		if (ci && bi && ve)
		    replyf(ctx, MSG_protected_cipher, ci, bi, ve);
		else
		    reply(ctx, MSG_handshake);
	    } else
		reply(ctx, MSG_protected);
	} else
	    reply(ctx, MSG_unprotected);
#endif				/* WITH_SSL */

	replyf(ctx, MSG_Transport_protocol,
#ifdef IPPROTO_SCTP
	       ctx->protocol == IPPROTO_SCTP ? "SCTP" :
#endif
	       "TCP");

	if (ctx->idle_timeout)
	    replyf(ctx, MSG_Idle_timeout, ctx->idle_timeout);

	if (ctx->dfn > -1) {
	    if (ctx->ffn > -1 && ctx->filename[0]) {
		if (ctx->use_ascii || ctx->conversion != CONV_NONE || ctx->mode == 'z')
		    replyf(ctx, MSG_Data_transfer_ascii, (unsigned long long) ctx->bytecount);
		else
		    replyf(ctx, MSG_Data_transfer, (unsigned long long) ctx->bytecount, (unsigned long long) ctx->filesize);
	    } else
		reply(ctx, MSG_Data_idle);
	}
	replyf(ctx, MSG_Data_total, ctx->traffic_total);
	reply(ctx, MSG_211_Server_status_END);
    }
    DebugOut(DEBUG_COMMAND);
}

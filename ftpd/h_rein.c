/*
 * h_rein.c
 *
 * (C)1998-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include "headers.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

#ifdef WITH_SSL
static void do_shutdown(struct context *ctx, int cur)
{
    Debug((DEBUG_PROC, "do_shutdown\n"));

    if (io_SSL_shutdown(ctx->ssl_c, ctx->io, cur, (void *) do_shutdown)
	< 0 && errno == EAGAIN)
	return;

    io_clr_i(ctx->io, cur);
    io_clr_o(ctx->io, cur);

    SSL_free(ctx->ssl_c);
    ctx->ssl_c = NULL;

    ctx->use_tls_d = 0;
    ctx->protected_buffer_size = -1;

    io_set_cb_e(ctx->io, cur, (void *) cleanup_control);
    io_set_cb_h(ctx->io, cur, (void *) cleanup_control);

    print_banner(ctx);
}

static void desslify(struct context *ctx, int cur)
{
    if (ctx->cbufo && ctx->cbufo->length - ctx->cbufo->offset)
	control2socket(ctx, cur);
    if (ctx->cbufo && ctx->cbufo->length - ctx->cbufo->offset)
	io_set_cb_o(ctx->io, cur, (void *) do_shutdown);
    else {
	io_clr_i(ctx->io, cur);
	io_clr_o(ctx->io, cur);
	do_shutdown(ctx, cur);
    }
}
#endif				/* WITH_SSL */

void h_rein(struct context *ctx, char *arg __attribute__((unused)))
{
    DebugIn(DEBUG_COMMAND);
    cleanup_file(ctx, ctx->ffn);
#ifdef WITH_SSL
    if (ctx->ssl_d) {
	SSL_free(ctx->ssl_d);
	ctx->ssl_d = NULL;
    }
#endif				/* WITH_SSL */
    cleanup_data(ctx, ctx->dfn);
    Xfree(&ctx->user);
    Xfree(&ctx->email);
    Xfree(&ctx->vhost);
    Xfree(&ctx->visited_dirs);
    ctx->dbuf = buffer_free_all(ctx->dbuf);
    if (ctx->incoming) {
	regfree(ctx->incoming);
	free(ctx->incoming);
	ctx->incoming = NULL;
    }

    ctx->multiline_banners = 1;
    ctx->real = ctx->anonymous = 0;
    ctx->outgoing_data = ctx->use_ascii = 1;
    ctx->io_offset = 0;
    ctx->io_offset_start = 0;
    ctx->io_offset_end = -1;
    ctx->state = ST_conn;
    ctx->uid = -1;
    ctx->gid = -1;
    ctx->mlst_facts = MLST_fact_size | MLST_fact_modify | MLST_fact_type | MLST_fact_unique | MLST_fact_perm;

    ctx->pst_valid = 0;
    ctx->mode = 's';

    ctx->md_method_hash = ctx->md_method_checksum = md_method_find(md_methods, "SHA-1");
    if (!ctx->md_method_hash)
	ctx->md_method_hash = ctx->md_method_checksum = md_method_find(md_methods, "MD5");

    acl_calc(ctx);

#ifdef WITH_SSL
    if (!ctx->ssl_c || ctx->use_tls_c)	/* no TLS or implicit TLS via port */
	print_banner(ctx);
    else
	desslify(ctx, ctx->cfn);
#else				/* WITH_SSL */
    print_banner(ctx);
#endif				/* WITH_SSL */

    DebugOut(DEBUG_COMMAND);
}

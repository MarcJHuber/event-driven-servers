/*
 * mavis_glue.c
 * (C)1998-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * Glue code and public interface functions for MAVIS modules.
 *
 * $Id$
 *
 */

static const char mavis_glue_rcsid[] __attribute__((used)) = "$Id$";

#include "log.h"
#include "misc/version.h"

static int Mavis_init(mavis_ctx * mcx)
{
    int result = MAVIS_INIT_OK;
#ifdef HAVE_mavis_init_out
    int tmp_result = MAVIS_INIT_OK;
#endif
    DebugIn(DEBUG_MAVIS);

    mavis_check_version(MAVIS_API_VERSION);

#ifdef HAVE_mavis_init_in
    result = mavis_init_in(mcx);
#endif

    if (mcx->down)
	result = mcx->down->init(mcx->down);

#ifdef HAVE_mavis_init_out
    tmp_result = mavis_init_out(mcx);
    if (result == MAVIS_INIT_OK)
	result = tmp_result;
#endif

    Debug((DEBUG_MAVIS, "- " MAVIS_name ":%s = %d\n", __func__, result));
    return result;
}

static void *Mavis_drop(mavis_ctx * mcx)
{
    void *handle = NULL;
    DebugIn(DEBUG_MAVIS);

#ifdef HAVE_mavis_drop_in
    mavis_drop_in(mcx);
#endif

    if (mcx->down)
	dlclose(mcx->down->drop(mcx->down));

#ifdef HAVE_mavis_drop_out
    mavis_drop_out(mcx);
#endif

    mavis_script_drop(&mcx->script_in);
    mavis_script_drop(&mcx->script_out);

    av_free(mcx->ac_bak);
    mcx->ac_bak = NULL;

    handle = mcx->handle;

    if (mcx->identifier)
	free(mcx->identifier);
    if (mcx->identity_source_name)
	free(mcx->identity_source_name);

    free(mcx);

    DebugOut(DEBUG_MAVIS);
    return handle;
}

static int Mavis_parse(mavis_ctx * mcx, struct sym *sym, char *id)
{
    int result = MAVIS_CONF_ERR;
    DebugIn(DEBUG_MAVIS);

#ifdef HAVE_mavis_parse_in
    if (!strcmp(id, mcx->identifier))
	result = mavis_parse_in(mcx, sym);
    else
#endif
    if (mcx->down) {
	result = mcx->down->parse(mcx->down, sym, id);
	if (result != MAVIS_CONF_OK)
	    result = MAVIS_CONF_ERR;
    }

    Debug((DEBUG_MAVIS, "- " MAVIS_name ":%s = %d\n", __func__, result));
    return result;
}

static int Mavis_send(mavis_ctx * mcx, av_ctx ** ac)
{
    int result = MAVIS_DOWN;
    char *current_module = av_get(*ac, AV_A_CURRENT_MODULE);
    DebugIn(DEBUG_MAVIS);

    if (!current_module) {

	if (mcx->ac_bak_required) {
	    if (!mcx->ac_bak)
		mcx->ac_bak = av_new(NULL, NULL);
	    av_copy(mcx->ac_bak, *ac);
	}

	if (mcx->script_in) {
	    switch (mavis_script_eval(mcx, *ac, mcx->script_in)) {
	    case S_skip:
		break;
	    case S_return:
		if (mcx->script_out)
		    mavis_script_eval(mcx, *ac, mcx->script_out);
		DebugOut(DEBUG_MAVIS);
		return MAVIS_FINAL;
	    default:;
#ifdef HAVE_mavis_send_in
		result = mavis_send_in(mcx, ac);
#endif
	    }
	}
#ifdef HAVE_mavis_send_in
	else
	    result = mavis_send_in(mcx, ac);
#endif
    }
    if (current_module && !strcmp(mcx->identifier, current_module)) {
	result = mcx->last_result;
	av_unset(*ac, AV_A_CURRENT_MODULE);
    }

    if (result == MAVIS_DOWN && mcx->down)
	result = mcx->down->send(mcx->down, ac);

#ifdef HAVE_mavis_recv_out
    if (result == MAVIS_FINAL)
	result = mavis_recv_out(mcx, ac);
#endif

    if (result == MAVIS_DOWN)
	result = MAVIS_FINAL;

    if (mcx->script_out && result == MAVIS_FINAL)
	mavis_script_eval(mcx, *ac, mcx->script_out);

    Debug((DEBUG_MAVIS, "- " MAVIS_name ":%s = %d\n", __func__, result));
    return result;
}

static int Mavis_cancel(mavis_ctx * mcx, void *app_ctx)
{
    int result = MAVIS_DOWN;

    DebugIn(DEBUG_MAVIS);

#ifdef HAVE_mavis_cancel_in
    result = mavis_cancel_in(mcx, app_ctx);
#endif

    if (result == MAVIS_DOWN && mcx->down)
	result = mcx->down->cancel(mcx->down, app_ctx);

    if (result == MAVIS_DOWN)
	result = MAVIS_FINAL;

    Debug((DEBUG_MAVIS, "- " MAVIS_name ":%s = %d\n", __func__, result));
    return result;
}

static int Mavis_recv(mavis_ctx * mcx, av_ctx ** ac, void *app_ctx)
{
    int result = MAVIS_DOWN;
    DebugIn(DEBUG_MAVIS);

#ifdef HAVE_mavis_recv_in
    result = mavis_recv_in(mcx, ac, app_ctx);
#endif

    if (result == MAVIS_DOWN && mcx->down)
	result = mcx->down->recv(mcx->down, ac, app_ctx);

#ifdef HAVE_mavis_recv_out
    if (result == MAVIS_FINAL)
	result = mavis_recv_out(mcx, ac);
#endif

    if (result == MAVIS_DOWN)
	result = MAVIS_FINAL;

    if (mcx->script_out && result == MAVIS_FINAL)
	mavis_script_eval(mcx, *ac, mcx->script_out);

    Debug((DEBUG_MAVIS, "- " MAVIS_name ":%s = %d\n", __func__, result));
    return result;
}

static int Mavis_append(mavis_ctx * mcx, void *m)
{
    if (mcx->down) {
	mcx->down->top = mcx->top;
	return mcx->down->append(mcx->down, m);
    }
    ((mavis_ctx *) m)->top = mcx->top;
    mcx->down = m;
    return 0;
}

mavis_ctx *Mavis_new(void *handle, struct io_context *io, char *id)
{
    mavis_ctx *mcx = Xcalloc(1, sizeof(mavis_ctx) + strlen(id ? id : MAVIS_name));
    mcx->handle = handle;
    mcx->append = Mavis_append;
    mcx->init = Mavis_init;
    mcx->drop = Mavis_drop;
    mcx->send = Mavis_send;
    mcx->recv = Mavis_recv;
    mcx->parse = Mavis_parse;
    mcx->cancel = Mavis_cancel;
    mcx->io = io;
    mcx->identifier = strdup(id ? id : MAVIS_name);
#ifdef HAVE_mavis_new
    mavis_new(mcx);
#endif
    return mcx;
}

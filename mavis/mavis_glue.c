/*
 * mavis_glue.c
 * (C)1998-2023 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * Glue code and public interface functions for MAVIS modules.
 *
 * $Id$
 *
 */

static const char mavis_glue_rcsid[] __attribute__((used)) = "$Id$";

#include <stdio.h>
#include "log.h"
#include "misc/rb.h"
#include "misc/version.h"

static int Mavis_init(mavis_ctx * mcx)
{
    int result = MAVIS_INIT_OK;
#ifdef HAVE_mavis_init_out
    int tmp_result = MAVIS_INIT_OK;
#endif
    DebugIn(DEBUG_MAVIS);

    mavis_check_version(MAVIS_API_VERSION, MAVIS_TOKEN_VERSION);

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
    DebugIn(DEBUG_MAVIS);

#ifdef HAVE_mavis_drop_in
    mavis_drop_in(mcx);
#endif

    if (mcx->down)
	dlclose(mcx->down->drop(mcx->down));

#ifdef HAVE_mavis_drop_out
    mavis_drop_out(mcx);
#endif

    mavis_script_drop(&mcx->script_interim);
    mavis_script_drop(&mcx->script_in);
    mavis_script_drop(&mcx->script_out);

    void *handle = handle = mcx->handle;

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
    DebugIn(DEBUG_MAVIS);

    int result = MAVIS_CONF_ERR;
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

#if defined(HAVE_mavis_send_in) || defined(HAVE_mavis_recv_out) || defined(HAVE_mavis_recv_in)
static int fixup_result(mavis_ctx * mcx, av_ctx ** ac, int result)
{
    if (*ac && (result == MAVIS_FINAL || result == MAVIS_FINAL_DEFERRED)) {
	char *avres = av_get(*ac, AV_A_RESULT);
	if (mcx->down && avres && mcx->action_error == S_continue && !strcmp(avres, AV_V_RESULT_ERROR)) {
	    av_unset(*ac, AV_A_USER_RESPONSE);
	    av_set(*ac, AV_A_RESULT, AV_V_RESULT_NOTFOUND);
	    return MAVIS_DOWN;
	}
	if (mcx->down && avres && mcx->action_notfound == S_continue && !strcmp(avres, AV_V_RESULT_NOTFOUND)) {
	    av_unset(*ac, AV_A_USER_RESPONSE);
	    av_set(*ac, AV_A_RESULT, AV_V_RESULT_NOTFOUND);
	    return MAVIS_DOWN;
	}
    } else if (*ac && (result == MAVIS_DOWN)) {
	char *avres = av_get(*ac, AV_A_RESULT);
	if (avres && mcx->action_notfound == S_reject && !strcmp(avres, AV_V_RESULT_NOTFOUND)) {
	    av_set(*ac, AV_A_RESULT, AV_V_RESULT_FAIL);
	    return MAVIS_FINAL;
	}
    }
    return result;
}
#endif

static int Mavis_send(mavis_ctx * mcx, av_ctx ** ac)
{
    DebugIn(DEBUG_MAVIS);
    int result = MAVIS_DOWN;
    char *current_module = av_get(*ac, AV_A_CURRENT_MODULE);
    enum token script_verdict = S_unknown;

    if (!current_module) {
	if (mcx->script_in) {
	    script_verdict = mavis_script_eval(mcx, *ac, mcx->script_in);
	    switch (script_verdict) {
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
		result = fixup_result(mcx, ac, result);
#endif
	    }
	}
#ifdef HAVE_mavis_send_in
	else {
	    result = mavis_send_in(mcx, ac);
	    result = fixup_result(mcx, ac, result);
	}
#endif
    }
    if (current_module && !strcmp(mcx->identifier, current_module)) {
	result = mcx->last_result;
	av_unset(*ac, AV_A_CURRENT_MODULE);
    }

    if (result == MAVIS_DOWN && mcx->down && *ac)
	result = mcx->down->send(mcx->down, ac);

#ifdef HAVE_mavis_recv_out
    if (result == MAVIS_FINAL && script_verdict != S_skip) {
	if (mcx->script_interim)
	    script_verdict = mavis_script_eval(mcx, *ac, mcx->script_interim);
	switch (script_verdict) {
	case S_skip:
	    break;
	default:
	    result = mavis_recv_out(mcx, ac);
	    result = fixup_result(mcx, ac, result);
	}
    }
#endif

    if (result == MAVIS_DOWN)
	result = MAVIS_FINAL;

    if (mcx->script_out && result == MAVIS_FINAL && script_verdict != S_skip)
	mavis_script_eval(mcx, *ac, mcx->script_out);

    Debug((DEBUG_MAVIS, "- " MAVIS_name ":%s = %d\n", __func__, result));
    return result;
}

static int Mavis_cancel(mavis_ctx * mcx, void *app_ctx)
{
    DebugIn(DEBUG_MAVIS);

    int result = MAVIS_DOWN;

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
    DebugIn(DEBUG_MAVIS);

    int result = MAVIS_DOWN;
#ifdef HAVE_mavis_recv_in
    result = mavis_recv_in(mcx, ac, app_ctx);
    result = fixup_result(mcx, ac, result);
#endif
    if (result == MAVIS_DOWN && mcx->down && *ac)
	result = mcx->down->send(mcx->down, ac);

    if (result == MAVIS_DOWN && mcx->down)
	result = mcx->down->recv(mcx->down, ac, app_ctx);

    if (result == MAVIS_FINAL && mcx->script_interim) {
	switch (mavis_script_eval(mcx, *ac, mcx->script_interim)) {
	case S_skip:
	    goto bye;
	case S_return:
	    goto bye2;
	default:;
	}
    }
#ifdef HAVE_mavis_recv_out
    if (result == MAVIS_FINAL) {
	result = mavis_recv_out(mcx, ac);
	result = fixup_result(mcx, ac, result);
	if (result == MAVIS_DOWN && mcx->down && *ac)
	    result = mcx->down->send(mcx->down, ac);
    }
#endif

    if (result == MAVIS_DOWN)
	result = MAVIS_FINAL;
  bye2:
    if (mcx->script_out && result == MAVIS_FINAL)
	mavis_script_eval(mcx, *ac, mcx->script_out);

  bye:
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
    mcx->action_error = S_reject;
    mcx->action_notfound = S_continue;
#ifdef HAVE_mavis_new
    mavis_new(mcx);
#endif
    return mcx;
}

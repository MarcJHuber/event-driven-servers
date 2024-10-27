/*
   Copyright (C) 1999-2022 Marc Huber (Marc.Huber@web.de)
   All rights reserved.

   Redistribution and use in source and binary  forms,  with or without
   modification, are permitted provided  that  the following conditions
   are met:

   1. Redistributions of source code  must  retain  the above copyright
      notice, this list of conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions  and  the following disclaimer in
      the  documentation  and/or  other  materials  provided  with  the
      distribution.

   3. The end-user documentation  included with the redistribution,  if
      any, must include the following acknowledgment:

          This product includes software developed by Marc Huber
	  (Marc.Huber@web.de).

      Alternately,  this  acknowledgment  may  appear  in  the software
      itself, if and wherever such third-party acknowledgments normally
      appear.

   THIS SOFTWARE IS  PROVIDED  ``AS IS''  AND  ANY EXPRESSED OR IMPLIED
   WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
   MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
   IN NO EVENT SHALL  ITS  AUTHOR  BE  LIABLE FOR ANY DIRECT, INDIRECT,
   INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
   BUT NOT LIMITED  TO,  PROCUREMENT OF  SUBSTITUTE  GOODS OR SERVICES;
   LOSS OF USE,  DATA,  OR PROFITS;  OR  BUSINESS INTERRUPTION) HOWEVER
   CAUSED AND ON ANY THEORY OF LIABILITY,  WHETHER IN CONTRACT,  STRICT
   LIABILITY,  OR TORT  (INCLUDING NEGLIGENCE OR OTHERWISE)  ARISING IN
   ANY WAY OUT OF THE  USE  OF  THIS  SOFTWARE,  EVEN IF ADVISED OF THE
   POSSIBILITY OF SUCH DAMAGE.
 */

#include "headers.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

struct shellctx {
    struct in6_addr nas_address;
    char *username;
    char *portname;
    char *ctxname;
    time_t expires;
    char data[2];
};

static int shellctx_cmp(const void *a, const void *b)
{
    int i = strcmp(((struct shellctx *) a)->username, ((struct shellctx *) b)->username);
    if (i)
	return i;
    i = strcmp(((struct shellctx *) a)->portname, ((struct shellctx *) b)->portname);
    if (i)
	return i;
    return memcmp(&((struct shellctx *) a)->nas_address, &((struct shellctx *) b)->nas_address, sizeof(struct in6_addr));
}


static void shellctx_free(void *payload)
{
    free(((struct shellctx *) payload)->ctxname);
    free(payload);
}


static rb_node_t *tac_script_lookup_exec_context(tac_session * session)
{
    if (!session->ctx->shellctxcache)
	return NULL;
    struct shellctx sc = { .username = session->username, .portname = session->nas_port };
    memcpy(&sc.nas_address, &session->ctx->nas_address, sizeof(struct in6_addr));
    return RB_search(session->ctx->shellctxcache, &sc);
}

void tac_script_set_exec_context(tac_session * session, char *ctxname)
{
    rb_node_t *rb = NULL;
    struct shellctx *sc;

    if (!session->ctx->single_connection_flag) {
	if (!session->ctx->single_connection_did_warn) {
	    session->ctx->single_connection_did_warn = BISTATE_YES;
	    report(session, LOG_INFO, ~0,
		   "%s: Possibly no single-connection support. " "Context feature may or may not work.", session->ctx->nas_address_ascii);
	}
    }

    if (!session->ctx->shellctxcache && (!ctxname || !*ctxname))
	return;

    if (session->ctx->shellctxcache)
	rb = tac_script_lookup_exec_context(session);
    else
	session->ctx->shellctxcache = RB_tree_new(shellctx_cmp, shellctx_free);

    if (rb) {
	if (!ctxname || !*ctxname) {
	    RB_delete(session->ctx->shellctxcache, rb);
	    return;
	}
	sc = RB_payload(rb, struct shellctx *);
	free(sc->ctxname);
    } else {
	sc = calloc(1, sizeof(struct shellctx) + session->username_len + session->nas_port_len);
	sc->username = sc->data;
	sc->portname = sc->data + session->username_len + 1;
	memcpy(sc->username, session->username, session->username_len);
	memcpy(sc->portname, session->nas_port, session->nas_port_len);
	memcpy(&sc->nas_address, &session->ctx->nas_address, sizeof(struct in6_addr));
	RB_insert(session->ctx->shellctxcache, sc);
    }
    sc->ctxname = strdup(ctxname);
    sc->expires = io_now.tv_sec + session->ctx->host->context_timeout;
}

char *tac_script_get_exec_context(tac_session * session)
{
    rb_node_t *rb = tac_script_lookup_exec_context(session);
    if (rb) {
	RB_payload(rb, struct shellctx *)->expires = io_now.tv_sec + session->ctx->host->context_timeout;
	return RB_payload(rb, struct shellctx *)->ctxname;
    }
    return NULL;
}

void tac_script_expire_exec_context(struct context *ctx)
{

    if (ctx->shellctxcache) {
	for (rb_node_t *rbnext, *rbn = RB_first(ctx->shellctxcache); rbn; rbn = rbnext) {
	    time_t v = RB_payload(rbn, struct shellctx *)->expires;
	    rbnext = RB_next(rbn);
	    if (v < io_now.tv_sec)
		RB_delete(ctx->shellctxcache, rbn);
	}
    }
}

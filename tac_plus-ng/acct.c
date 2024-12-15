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

/* 
   Copyright (c) 1995-1998 by Cisco systems, Inc.

   Permission to use, copy, modify, and distribute this software for
   any purpose and without fee is hereby granted, provided that this
   copyright and permission notice appear on all copies of the
   software and supporting documentation, the name of Cisco Systems,
   Inc. not be used in advertising or publicity pertaining to
   distribution of the program without specific prior permission, and
   notice be given in supporting documentation that modification,
   copying and distribution is by permission of Cisco Systems, Inc.

   Cisco Systems, Inc. makes no representations about the suitability
   of this software for any purpose.  THIS SOFTWARE IS PROVIDED ``AS
   IS'' AND WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING,
   WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
   FITNESS FOR A PARTICULAR PURPOSE.
*/

#include "headers.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

static void do_acct(tac_session *);

void accounting(tac_session *session, tac_pak_hdr *hdr)
{
    struct acct *acct = tac_payload(hdr, struct acct *);
    u_char *p = (u_char *) acct + TAC_ACCT_REQ_FIXED_FIELDS_SIZE + acct->arg_cnt;
    tac_host *h = session->ctx->host;

    report(session, LOG_DEBUG, DEBUG_ACCT_FLAG, "Start accounting request");

    session->priv_lvl = acct->priv_lvl;
    session->privlvl_len = snprintf(session->privlvl, sizeof(session->privlvl), "%u", session->priv_lvl);

    if (acct->flags & TAC_PLUS_ACCT_FLAG_STOP) {
#define S "stop"
	str_set(&session->acct_type, S, sizeof(S) - 1);
#undef S
#define S "ACCT-STOP"
	str_set(&session->msgid, S, sizeof(S) - 1);
#undef S
    } else if (acct->flags & TAC_PLUS_ACCT_FLAG_START) {
#define S "start"
	str_set(&session->acct_type, S, sizeof(S) - 1);
#undef S
#define S "ACCT-START"
	str_set(&session->msgid, S, sizeof(S) - 1);
#undef S
    } else if (acct->flags & TAC_PLUS_ACCT_FLAG_WATCHDOG) {
#define S "update"
	str_set(&session->acct_type, S, sizeof(S) - 1);
#undef S
#define S "ACCT-UPDATE"
	str_set(&session->msgid, S, sizeof(S) - 1);
#undef S
    } else {
#define S "unknown"
	str_set(&session->acct_type, S, sizeof(S) - 1);
#undef S
#define S "ACCT-UNKNOWN"
	str_set(&session->msgid, S, sizeof(S) - 1);
#undef S
    }

    str_set(&session->username, mem_strndup(session->mem, p, acct->user_len), acct->user_len);

    // script-based user rewriting, current
    enum token res = S_unknown;
    while (h && res != S_permit && res != S_deny) {
	if (h->action)
	    res = tac_script_eval_r(session, h->action);
	h = h->parent;
    }

    p += acct->user_len;
    str_set(&session->port, mem_strndup(session->mem, p, acct->port_len), acct->port_len);
    p += acct->port_len;
    str_set(&session->nac_addr_ascii, mem_strndup(session->mem, p, acct->rem_addr_len), acct->rem_addr_len);
    p += acct->rem_addr_len;
    session->argp = p;
    session->arg_cnt = acct->arg_cnt;
    session->arg_len = (u_char *) acct + TAC_ACCT_REQ_FIXED_FIELDS_SIZE;

    eval_args(session, p, session->arg_len, session->arg_cnt);

    session->nac_addr_valid = v6_ptoh(&session->nac_address, NULL, session->nac_addr_ascii.txt) ? 0 : 1;
    if (session->nac_addr_valid)
	get_revmap_nac(session);

    if (acct->flags & TAC_PLUS_ACCT_FLAG_STOP && session->service.txt && !strcmp(session->service.txt, "shell"))
	tac_script_set_exec_context(session, NULL);

#ifdef WITH_DNS
    if ((session->ctx->host->dns_timeout > 0) && (session->revmap_pending || session->ctx->revmap_pending)) {
	session->resumefn = do_acct;
	io_sched_add(session->ctx->io, session, (void *) resume_session, session->ctx->host->dns_timeout, 0);
    } else
#endif
	do_acct(session);
}

static void do_acct(tac_session *session)
{
    log_exec(session, session->ctx, S_accounting, io_now.tv_sec);
    send_acct_reply(session, TAC_PLUS_ACCT_STATUS_SUCCESS, NULL, NULL);
}


static void do_rad_acct(tac_session *);

void rad_acct(tac_session *session)
{
    tac_host *h = session->ctx->host;

    rad_set_fields(session);

    report(session, LOG_DEBUG, DEBUG_ACCT_FLAG, "Start accounting request");

    int type = 0;
    if (!rad_get(session, -1, RADIUS_A_ACCT_STATUS_TYPE, S_integer, &type, NULL)) {
	switch (type) {
	case RADIUS_V_ACCT_STATUS_TYPE_START:
#define S "start"
	    str_set(&session->acct_type, S, sizeof(S) - 1);
#undef S
#define S "ACCT-START"
	    str_set(&session->msgid, S, sizeof(S) - 1);
#undef S
	    break;
	case RADIUS_V_ACCT_STATUS_TYPE_STOP:
#define S "stop"
	    str_set(&session->acct_type, S, sizeof(S) - 1);
#undef S
#define S "ACCT-STOP"
	    str_set(&session->msgid, S, sizeof(S) - 1);
#undef S
	    break;
	case RADIUS_V_ACCT_STATUS_TYPE_INTERIM_UPDATE:
#define S "update"
	    str_set(&session->acct_type, S, sizeof(S) - 1);
#undef S
#define S "ACCT-UPDATE"
	    str_set(&session->msgid, S, sizeof(S) - 1);
#undef S
	    break;
	case RADIUS_V_ACCT_STATUS_TYPE_ACCOUNTING_ON:
#define S "on"
	    str_set(&session->acct_type, S, sizeof(S) - 1);
#undef S
#define S "ACCT-ON"
	    str_set(&session->msgid, S, sizeof(S) - 1);
#undef S
	case RADIUS_V_ACCT_STATUS_TYPE_ACCTOUNTING_OFF:
#define S "off"
	    str_set(&session->acct_type, S, sizeof(S) - 1);
#undef S
#define S "ACCT-OFF"
	    str_set(&session->msgid, S, sizeof(S) - 1);
#undef S
	default:
#define S "unknown"
	    str_set(&session->acct_type, S, sizeof(S) - 1);
#undef S
#define S "ACCT-UNKNOWN"
	    str_set(&session->msgid, S, sizeof(S) - 1);
#undef S
	}
    }
    // script-based user rewriting, current
    enum token res = S_unknown;
    while (h && res != S_permit && res != S_deny) {
	if (h->action)
	    res = tac_script_eval_r(session, h->action);
	h = h->parent;
    }

    if (session->nac_addr_valid)
	get_revmap_nac(session);

#ifdef WITH_DNS
    if ((session->ctx->host->dns_timeout > 0) && (session->revmap_pending || session->ctx->revmap_pending)) {
	session->resumefn = do_rad_acct;
	io_sched_add(session->ctx->io, session, (void *) resume_session, session->ctx->host->dns_timeout, 0);
    } else
#endif
	do_rad_acct(session);
}

static void do_rad_acct(tac_session *session)
{
    log_exec(session, session->ctx, S_radius_accounting, io_now.tv_sec);
    rad_send_acct_reply(session);
}

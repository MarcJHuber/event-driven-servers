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
   
   Permission to use, copy, modify, and distribute this software for any purpose
   and without fee is hereby granted, provided that this copyright and
   permission notice appear on all copies of the software and supporting
   documentation, the name of Cisco Systems, Inc. not be used in advertising
   or publicity pertaining to distribution of the program without specific
   prior permission, and notice be given in supporting documentation that
   modification, copying and distribution is by permission of Cisco Systems,
   Inc.
   
   Cisco Systems, Inc. makes no representations about the suitability of this
   software for any purpose.  THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT
   ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE
   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
   PURPOSE.
 */

#include "headers.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

static void do_author(tac_session *);
static int bad_nas_args(tac_session *, struct author_data *);

void author(tac_session * session, tac_pak_hdr * hdr)
{
    u_char *p, *argsizep;
    char **cmd_argp;
    int i;
    struct author *pak = tac_payload(hdr, struct author *);
    struct author_data *data;
    enum token res = S_unknown;
    char *cmdline, *t;
    size_t len = 0, tlen = 0;
    tac_host *h = session->ctx->host;

    report(session, LOG_DEBUG, DEBUG_AUTHOR_FLAG, "Start authorization request");

    get_pkt_data(session, NULL, pak);

    /* start of variable length data is here */
    argsizep = p = (u_char *) pak + TAC_AUTHOR_REQ_FIXED_FIELDS_SIZE;

    /* arg length data starts here */
    p += pak->arg_cnt;

    session->pak_authen_type = pak->authen_type;
    session->pak_authen_method = pak->authen_method;
    session->username_len = (size_t) pak->user_len;
    session->username = memlist_strndup(session->memlist, p, session->username_len);
    p += pak->user_len;
    session->nas_port = memlist_strndup(session->memlist, p, (size_t) pak->port_len);
    session->nas_port_len = pak->port_len;
    p += pak->port_len;
    session->nac_address_ascii = memlist_strndup(session->memlist, p, (size_t) pak->rem_addr_len);
    session->nac_address_ascii_len = (size_t) pak->rem_addr_len;
    p += pak->rem_addr_len;

    session->argp = p;
    session->arg_len = argsizep;
    session->arg_cnt = pak->arg_cnt;

    session->priv_lvl = pak->priv_lvl;
    session->privlvl_len = snprintf(session->privlvl, sizeof(session->privlvl), "%u", session->priv_lvl);

    session->nac_address_valid = v6_ptoh(&session->nac_address, NULL, session->nac_address_ascii) ? 0 : 1;
    if (session->nac_address_valid)
	get_revmap_nac(session);

    data = memlist_malloc(session->memlist, sizeof(struct author_data));
    data->in_cnt = pak->arg_cnt;

    cmd_argp = memlist_malloc(session->memlist, pak->arg_cnt * sizeof(char *));

    /* p points to the start of args. Step thru them making strings */
    for (i = 0; i < (int) pak->arg_cnt; i++) {
	cmd_argp[i] = memlist_strndup(session->memlist, p, *argsizep);
	p += *argsizep++;
    }

    data->in_args = cmd_argp;	/* input command arguments */
    session->author_data = data;
    session->in_length = session->ctx->in->length;

    // script-based user rewriting, current
    while (h && res != S_permit && res != S_deny) {
	if (h->action)
	    res = tac_script_eval_r(session, h->action);
	h = h->parent;
    }

    // legacy user rewriting, deprecated
    tac_rewrite_user(session, NULL);

    t = cmdline = alloca(session->in_length);

    for (i = 0; i < data->in_cnt; i++) {
	size_t l = strlen(data->in_args[i]);
	char *a = data->in_args[i];
	if (l > 3 && (!strncmp(a, "cmd=", 4) || !strncmp(a, "cmd*", 4))) {
	    session->author_data->is_cmd = (l > 4);
	    len = l - 4;
	    memcpy(t, a + 4, len);
	    t += len;
	    tlen += len;
	} else if (l > 8 && !strncmp(a, "cmd-arg=", 8)) {
	    *t++ = ' ';
	    tlen++;
	    len = l - 8;
	    memcpy(t, a + 8, len);
	    t += len;
	    tlen += len;
	} else if (l > 8 && !strncmp(a, "service=", 8)) {
	    session->service_len = l - 8;
	    session->service = memlist_strndup(session->memlist, (u_char *) (a + 8), l - 8);
	    session->author_data->is_shell = !strcmp(session->service, "shell");
	} else if (l > 9 && !strncmp(a, "protocol=", 9)) {
	    session->protocol_len = l - 9;
	    session->protocol = memlist_strndup(session->memlist, (u_char *) (a + 9), l - 9);
	}
    }

    *t = 0;
    session->cmdline = memlist_strdup(session->memlist, cmdline);
    session->cmdline_len = tlen;

    if (bad_nas_args(session, data)) {
	send_author_reply(session, TAC_PLUS_AUTHOR_STATUS_FAIL, session->message, NULL, 0, NULL);
	return;
    }
#ifdef WITH_DNS
    if ((session->ctx->host->dns_timeout > 0) && (session->revmap_pending || session->ctx->revmap_pending)) {
	session->resumefn = do_author;
	io_sched_add(session->ctx->io, session, (void *) resume_session, session->ctx->host->dns_timeout, 0);
    } else
#endif
	do_author(session);
}

#define is_separator(A) ((A) == '=' || (A) == '*')

static int strcmp_a(char *a, char *b)
{
    while (*a && ((*a == *b) || (is_separator(*a) && is_separator(*b)))) {
	switch (*a) {
	case 0:
	case '=':
	case '*':
	    return 0;
	}
	a++, b++;
    }

    return (int) ((u_char) * a - (u_char) * b);
}

static int bad_nas_args(tac_session * session, struct author_data *data)
{
    int i;
    /* Check the nas args for well-formedness */
    for (i = 0; i < data->in_cnt; i++) {
	if (*(data->in_args[i])) {
	    size_t k = strcspn(data->in_args[i], "=*");
	    if (!k || !data->in_args[i][k]) {
		char buf[MAX_INPUT_LINE_LEN];
		snprintf(buf, sizeof(buf), "Illegal arg from NAS: %s", data->in_args[i]);
		data->status = TAC_PLUS_AUTHOR_STATUS_ERROR;
		data->admin_msg = memlist_strdup(session->memlist, buf);
		report(session, LOG_ERR, ~0, "%s: %s", session->ctx->nas_address_ascii, buf);
		return -1;
	    }
	}
    }
    return 0;
}

static char *lookup_attrval(char **attrs, int cnt, char *na)
{
    for (; cnt > 0; cnt--, attrs++) {
	if (*attrs && !strcmp(na, *attrs))
	    return *attrs;
    }
    return NULL;
}

static void clear_attrval(char **attrs, int cnt, char *na)
{
    for (; cnt > 0; cnt--, attrs++) {
	if (*attrs && !strcmp(na, *attrs)) {
	    *attrs = NULL;
	    return;
	}
    }
}

static char *lookup_attr(char **attrs, int cnt, char *na)
{
    size_t len = strcspn(na, "=*");
    if (len < strlen(na))
	return NULL;
    for (; cnt > -1; cnt--, attrs++) {
	if (*attrs && strlen(*attrs) > len && is_separator(*attrs[len]) && !strncmp(na, *attrs, len))
	    return *attrs;
    }
    return NULL;
}

static void do_author(tac_session * session)
{
    int i, replaced = 0, added = 0, out_cnt = 0;
    char **out_args, **outp;
    enum token res = S_unknown;
    struct author_data *data = session->author_data;
    tac_host *h = session->ctx->host;

    while (res != S_permit && res != S_deny && h) {
	if (h->action) {
	    static struct log_item *li_denied_by_acl = NULL;
	    res = tac_script_eval_r(session, h->action);
	    switch (res) {
	    case S_deny:
		if (!li_denied_by_acl)
		    li_denied_by_acl = parse_log_format_inline("\"${DENIED_BY_ACL}\"", __FILE__, __LINE__);
		report(session, LOG_DEBUG, DEBUG_AUTHOR_FLAG, "user %s realm %s denied by ACL", session->username, session->ctx->realm->name);
		send_author_reply(session, TAC_PLUS_AUTHOR_STATUS_FAIL, session->message,
				  eval_log_format(session, session->ctx, NULL, li_denied_by_acl, io_now.tv_sec, NULL), 0, NULL);
		return;
	    case S_permit:
		break;
	    default:
		break;
	    }
	}
	h = h->parent;
    }

    if (!session->user && session->username_len) {
	if (lookup_user(session)) {
	    session->debug |= session->user->debug;
	    if (session->profile)
		session->debug |= session->profile->debug;
	}
	if (query_mavis_info(session, do_author, PW_LOGIN))
	    return;
    }

    if (session->mavisauth_res == TAC_PLUS_AUTHEN_STATUS_ERROR) {
	report(session, LOG_DEBUG, DEBUG_AUTHOR_FLAG, "user '%s': backend failure", session->username);
	send_author_reply(session, TAC_PLUS_AUTHOR_STATUS_ERROR, session->message, NULL, 0, NULL);
	return;
    }

    if (!session->user) {
	if ((session->ctx->host->authz_if_authc == TRISTATE_YES) && session->pak_authen_method != TAC_PLUS_AUTHEN_METH_TACACSPLUS
	    && session->pak_authen_type == TAC_PLUS_AUTHEN_TYPE_ASCII) {
	    report(session, LOG_DEBUG, DEBUG_AUTHOR_FLAG, "user '%s' not found but authenticated locally, permitted by default", session->username);
	    send_author_reply(session, TAC_PLUS_AUTHOR_STATUS_PASS_ADD, session->message, NULL, 0, NULL);
	    return;
	}
	report(session, LOG_DEBUG, DEBUG_AUTHOR_FLAG, "user '%s' not found, denied by default", session->username);
	send_author_reply(session, TAC_PLUS_AUTHOR_STATUS_FAIL, session->message, NULL, 0, NULL);
	return;
    }

    session->debug |= session->user->debug;
    if (session->profile)
	session->debug |= session->profile->debug;

    report(session, LOG_DEBUG, DEBUG_AUTHOR_FLAG, "user '%s' found", session->username);

    if (session->authorized)
	res = S_permit;
    else {
	tac_profile *profile;
	res = eval_ruleset(session, session->ctx->realm);
	profile = session->profile;
	if (res == S_permit) {
	    res = S_unknown;
	    while (profile && res == S_unknown) {
		res = tac_script_eval_r(session, profile->action);
		profile = profile->parent;
	    }
	}
    }

    switch (res) {
    case S_deny:
	report(session, LOG_DEBUG, DEBUG_AUTHOR_FLAG,
	       "%s@%s: svcname=%s protocol=%s denied", session->username, session->ctx->nas_address_ascii, session->service ? session->service : "",
	       session->protocol ? session->protocol : "");
	send_author_reply(session, TAC_PLUS_AUTHOR_STATUS_FAIL, session->message, NULL, 0, NULL);
	return;
    default:
	report(session, LOG_DEBUG, DEBUG_AUTHOR_FLAG,
	       "%s@%s: svcname=%s protocol=%s not found",
	       session->username, session->ctx->nas_address_ascii, session->service ? session->service : "", session->protocol ? session->protocol : "");
	send_author_reply(session, TAC_PLUS_AUTHOR_STATUS_FAIL, session->message, NULL, 0, NULL);
	return;
    case S_permit:
	data->status = TAC_PLUS_AUTHOR_STATUS_PASS_ADD;
	if (session->author_data->is_shell && session->author_data->is_cmd) {	// shortcut for command authorization, shell authz will take the regular way.
	    send_author_reply(session, data->status, session->message, data->admin_msg, 0, NULL);
	    return;
	}
    }

    if (session->authorized && session->user->avc && session->user->avc->arr[AV_A_RARGS]) {
	char *a = session->user->avc->arr[AV_A_RARGS];
	while (*a) {
	    char *t = a;
	    char ***attr_p = NULL;
	    int *cnt_p = NULL;
	    char *plus = NULL;
	    for (; *t && *t != '\n' && !attr_p; t++) {
		switch (*t) {
		case '*':
		    attr_p = &session->attrs_o;
		    cnt_p = &session->cnt_o;
		    break;
		case '=':
		    attr_p = &session->attrs_m;
		    cnt_p = &session->cnt_m;
		    break;
		case '+':
		    attr_p = &session->attrs_a;
		    cnt_p = &session->cnt_a;
		    plus = t;
		    *plus = '*';
		    break;
		}
	    }
	    for (; *t && *t != '\n'; t++);
	    if (attr_p)
		attr_add(session, attr_p, cnt_p, a, t - a);
	    if (plus)
		*plus = '+';
	    if (!*t)
		break;
	    a = t;
	    a++;
	}
    }

    /* Allocate space for in + out args */
    out_args = memlist_malloc(session->memlist, sizeof(char *) * (data->in_cnt + session->cnt_m + session->cnt_a));

    outp = out_args;

    for (i = 0; i < data->in_cnt; i++) {
	char *da;		/* daemon arg */
	char *na;		/* nas arg */

	na = data->in_args[i];

	/* always pass these pairs through unchanged */
	if (!strcmp_a(na, "service=") || !strcmp_a(na, "protocol=") || !strcmp_a(na, "cmd=")) {

	    report(session, LOG_DEBUG, DEBUG_AUTHOR_FLAG, "nas:%s (passed thru)", na);
	    *outp++ = na, out_cnt++;
	    continue;
	}
	if (na[strcspn(na, "*=")] == '=') {
	    /* NAS AV pair is mandatory */

	    if ((da = lookup_attrval(session->attrs_m, session->cnt_m, na))) {
		report(session, LOG_DEBUG, DEBUG_AUTHOR_FLAG, "nas:%s, svr:%s -> add %s (%c)", na, da, da, 'a');
		*outp++ = da, out_cnt++;
		continue;
	    }

	    if ((da = lookup_attr(session->attrs_o, session->cnt_o, na))) {
		report(session, LOG_DEBUG, DEBUG_AUTHOR_FLAG, "nas:%s, svr:%s -> add %s (%c)", na, da, na, 'b');
		*outp++ = na, out_cnt++;
		continue;
	    }

	    /* If no attribute match exists, deny the attribute if the default
	     * is to deny */
	    if (session->attr_dflt != S_permit) {
		report(session, LOG_DEBUG, DEBUG_AUTHOR_FLAG, "nas:%s svr:absent/deny -> denied (c)", na);
		send_author_reply(session, TAC_PLUS_AUTHOR_STATUS_FAIL, session->message, NULL, 0, NULL);
		return;
	    }
	} else {
	    char c;
	    /* NAS AV pair is optional */

	    if ((c = 'e', da = lookup_attrval(session->attrs_m, session->cnt_m, na)) ||
		(c = 'f', da = lookup_attr(session->attrs_m, session->cnt_m, na)) || (c = 'g', da = lookup_attrval(session->attrs_o, session->cnt_o, na))
		|| (c = 'h', da = lookup_attrval(session->attrs_o, session->cnt_o, na))) {
		report(session, LOG_DEBUG, DEBUG_AUTHOR_FLAG, "nas:%s svr:%s -> replace with %s (%c)", na, da, da, c);
		*outp++ = da, out_cnt++, replaced++;
		continue;
	    }

	    /* If no match is found, delete the AV pair if default is deny */
	    if (session->attr_dflt != S_permit) {
		report(session, LOG_DEBUG, DEBUG_AUTHOR_FLAG, "nas:%s svr:absent/deny -> delete %s (i)", na, na);
		replaced++;
		continue;
	    }
	}

	/* If the default is permit, add the NAS AV pair to the output */
	report(session, LOG_DEBUG, DEBUG_AUTHOR_FLAG, "nas:%s svr:absent/permit -> add %s (d/j)", na, na);
	out_cnt++, *outp++ = na;
    }

    /*
     * After all AV pairs have been processed, for each mandatory
     * DAEMON AV pair, if there is no attribute match already in the
     * output list, add the AV pair (add only one AV pair for each
     * mandatory attribute)
     */

    for (i = 0; i < out_cnt; i++)
	clear_attrval(session->attrs_m, session->cnt_m, out_args[i]);

    for (i = 0; i < session->cnt_m; i++) {
	if (session->attrs_m[i]) {
	    /* Attr is required by daemon but not present. Add it */
	    report(session, LOG_DEBUG, DEBUG_AUTHOR_FLAG, "nas:absent srv:%s -> add %s (k)", session->attrs_m[i], session->attrs_m[i]);
	    added++, *outp++ = session->attrs_m[i], out_cnt++;
	}
    }

    /*
     * After all AV pairs have been processed, for each unrequested optional
     * DAEMON AV pair ("add"), if there is no attribute match already in the
     * output list, add the AV pair (add only one AV pair for each
     * unrequested optional attribute)
     */

    for (i = 0; i < out_cnt; i++)
	clear_attrval(session->attrs_a, session->cnt_a, out_args[i]);

    for (i = 0; i < session->cnt_a; i++)
	if (session->attrs_a[i]) {
	    /* Attr is required by daemon but not present. Add it */
	    report(session, LOG_DEBUG, DEBUG_AUTHOR_FLAG, "nas:absent srv:%s -> add %s (l)", session->attrs_a[i], session->attrs_a[i]);
	    added++, *outp++ = session->attrs_a[i];
	    out_cnt++;
	}

    if (replaced) {
	/*
	 * If we replaced or deleted some pairs we must return the entire
	 * list we've constructed.
	 */
	report(session, LOG_DEBUG, DEBUG_AUTHOR_FLAG, "replaced %d args", replaced);
	data->status = TAC_PLUS_AUTHOR_STATUS_PASS_REPL;
	data->out_args = out_args;
	data->out_cnt = out_cnt;
    } else {
	data->status = TAC_PLUS_AUTHOR_STATUS_PASS_ADD;

	if (added) {
	    /*
	     * We added something not on the original nas list, but didn't
	     * replace or delete anything. We should return only the additions.
	     */
	    report(session, LOG_DEBUG, DEBUG_AUTHOR_FLAG, "added %d args", added);
	    /* skip output args which are just copies of the input args */
	    data->out_args = out_args + data->in_cnt;
	    data->out_cnt = out_cnt - data->in_cnt;
	}
    }

    send_author_reply(session, data->status, session->message, data->admin_msg, data->out_cnt, data->out_args);
}

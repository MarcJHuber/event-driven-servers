/*
   Copyright (C) 1999-2020 Marc Huber (Marc.Huber@web.de)
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

struct author_data {
    char *server_msg;		/* user message (optional) */
    char *admin_msg;		/* admin message (optional) */
    int status;			/* return status */
    int in_cnt;			/* input arg count */
    char **in_args;		/* input arguments */
    int out_cnt;		/* output arg cnt */
    char **out_args;		/* output arguments */
};

static void do_author(tac_session *);

void author(tac_session * session, tac_pak_hdr * hdr)
{
    u_char *p, *argsizep;
    char **cmd_argp;
    int i;
    struct author *pak = tac_payload(hdr, struct author *);
    struct author_data *data;

    report(session, LOG_DEBUG, DEBUG_AUTHOR_FLAG, "Start authorization request");

    /* start of variable length data is here */
    argsizep = p = (u_char *) pak + TAC_AUTHOR_REQ_FIXED_FIELDS_SIZE;

    /* arg length data starts here */
    p += pak->arg_cnt;

    session->authen_type = pak->authen_type;
    session->authen_method = pak->authen_method;
    session->username = mem_strndup(session->mem, p, (int) pak->user_len);
    session->tag = strchr(session->username, session->ctx->aaa_realm->separator);
    if (session->tag)
	*session->tag++ = 0;
    tac_rewrite_user(session);
    p += pak->user_len;
    session->nas_port = mem_strndup(session->mem, p, (int) pak->port_len);
    p += pak->port_len;
    session->nac_address_ascii = mem_strndup(session->mem, p, (int) pak->rem_addr_len);
    p += pak->rem_addr_len;

    session->nac_address_valid = v6_ptoh(&session->nac_address, NULL, session->nac_address_ascii) ? 0 : 1;
    if (session->nac_address_valid) {
	tac_host *arr[129];
	int arr_min = 0, arr_max = 0, i;

	memset(arr, 0, sizeof(arr));

	if (radix_lookup(session->ctx->nac_realm->hosttree, &session->nac_address, (void *) arr)) {
	    for (arr_max = 0; arr_max < 129 && arr[arr_max]; arr_max++);
	    arr_max--;

	    for (i = arr_max; i > -1 && !arr[i]->orphan; i--);
	    arr_min = i;

	    for (i = arr_max; i > arr_min; i--)
		if (arr[i]->username) {
		    session->username_default = arr[i]->username;
		    break;
		}
	    for (i = arr_max; i > arr_min; i--)
		if (arr[i]->groupname) {
		    session->groupname_default = arr[i]->groupname;
		    break;
		}
	    get_revmap_nac(session, arr, arr_min, arr_max);
	}
    }

    session->priv_lvl = pak->priv_lvl;
    data = mem_alloc(session->mem, sizeof(struct author_data));
    data->in_cnt = pak->arg_cnt;

    cmd_argp = mem_alloc(session->mem, pak->arg_cnt * sizeof(char *));

    /* p points to the start of args. Step thru them making strings */
    for (i = 0; i < (int) pak->arg_cnt; i++) {
	cmd_argp[i] = mem_strndup(session->mem, p, *argsizep);
	p += *argsizep++;
    }

    data->in_args = cmd_argp;	/* input command arguments */
    session->author_data = data;

#ifdef WITH_DNS
    if ((session->dns_timeout > 0) && (session->revmap_pending || session->ctx->revmap_pending)) {
	session->resumefn = do_author;
	io_sched_add(session->ctx->io, session, (void *) resume_session, session->dns_timeout, 0);
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

static int strcmp_av(char *a, char *b)
{
    while (*a && ((*a == *b) || (is_separator(*a) && is_separator(*b))))
	a++, b++;

    return (int) ((u_char) * a - (u_char) * b);
}

/*
 * Return a node type indicating which kind of service is being requested. If
 * the service is a command authorisation request, also return the command
 * name in cmdname. If available, return the protocol name in protocol.
 * Return the name in svcname.
 */

static enum token get_nas_svc(struct author_data *data, char **cmdname, char **protocol, char **svcname)
{
    int i;

    *cmdname = NULL, *protocol = NULL, *svcname = NULL;
    for (i = 0; i < data->in_cnt; i++) {
	char *na = data->in_args[i];

	if (!strcmp_a(na, "service=")) {
	    enum token svc;
	    na += 8;
	    *svcname = na;
	    svc = keycode(na);

	    switch (svc) {
	    case S_shell:
		for (i = 0; i < data->in_cnt; i++) {
		    na = data->in_args[i];
		    if (!strcmp_a(na, "cmd=")) {
			if (na[4]) {
			    /* authorize a command */
			    *cmdname = na + 4;
			    return S_cmd;
			}
			/* authorize exec startup */
			return svc;
		    }
		}
#if 1
		// The client did violate the TACACS+ protocol specification
		// by not giving us a "cmd=" AV pair. Return the service
		// anyway, as well-behaving clients will never come that far.
		return svc;
#else
		return S_unknown;
#endif
	    default:
		for (i = 0; i < data->in_cnt; i++)
		    if (!strcmp_a(data->in_args[i], "protocol=")) {
			*protocol = data->in_args[i] + 9;
			break;
		    }
		return svc;
	    }
	}
    }
    return S_unknown;
}

static void log_author_cmd(tac_session * session, char *cmd, char *args)
{
    rb_tree_t *rbt = session->ctx->aaa_realm->author;

    if (rbt) {
	char *msgid = (session->author_data->status == TAC_PLUS_AUTHOR_STATUS_PASS_ADD) ? "AUTHZ-PERMIT" : "AUTHZ-DENY";
	log_start(rbt, session->ctx->nas_address_ascii, msgid);
	log_write(rbt, session->user->name, strlen(session->user->name));
	if (config.log_matched_group && session->final_match && (session->final_match != session->user->name)) {
	    log_write(rbt, "/", 1);
	    log_write(rbt, session->final_match, strlen(session->final_match));
	}
	log_write_separator(rbt);
	log_write(rbt, session->nas_port, strlen(session->nas_port));
	log_write_separator(rbt);
	log_write(rbt, session->nac_address_ascii, strlen(session->nac_address_ascii));
	log_write_separator(rbt);
	switch (session->author_data->status) {
	case TAC_PLUS_AUTHOR_STATUS_PASS_ADD:
	    log_write(rbt, codestring[S_permit].txt, codestring[S_permit].len);
	    break;
	default:
	    log_write(rbt, codestring[S_deny].txt, codestring[S_deny].len);
	    break;
	}
	log_write_separator(rbt);
	log_write(rbt, cmd, strlen(cmd));
	log_write_separator(rbt);
	log_write(rbt, args, strlen(args));
	log_flush(rbt);
    }
}

static void authorize_cmd(tac_session * session, char *cmd)
{
    struct author_data *data = session->author_data;
    int i, len = 0;
    char *args = "";
    char *format = NULL;

    for (i = 0; i < data->in_cnt; i++)
	if (!strcmp_a(data->in_args[i], "cmd-arg="))
	    len += (int) strlen(data->in_args[i] + 7);

    if (len) {
	args = mem_alloc(session->mem, len);
	*args = 0;
	for (i = 0; i < data->in_cnt; i++)
	    if (!strcmp_a(data->in_args[i], "cmd-arg=")) {
		if (*args)
		    strcat(args, " ");
		strcat(args, data->in_args[i] + 8);
	    }
    }

    switch (cfg_get_cmd_node(session, cmd, args, &format)) {
    case S_permit:
	data->status = TAC_PLUS_AUTHOR_STATUS_PASS_ADD;
	break;
    default:
	data->status = TAC_PLUS_AUTHOR_STATUS_FAIL;
    }

    if (format) {
	int l = 1;
	int cmdlen = cmd ? (int) strlen(cmd) : 0;
	int argslen = (int) strlen(args);
	char *q, *p = format;
	char *exec_context = "";
	int exec_context_len = 0;

	while (*p) {
	    if (p[0] == '%' && p[1] == 'a')
		p += 2, l += argslen;
	    else if (p[0] == '%' && p[1] == 'c')
		p += 2, l += cmdlen;
	    else if (p[0] == '%' && p[1] == 'C') {
		char *ec = tac_script_get_exec_context(session,
						       session->username,
						       session->nas_port);
		if (ec)
		    exec_context = ec, exec_context_len = strlen(exec_context);
		p += 2, l += exec_context_len;
	    } else
		p++, l++;
	}
	p = format;
	q = data->server_msg = mem_alloc(session->mem, l);
	while (*p) {
	    if (p[0] == '%' && p[1] == 'a') {
		strcpy(q, args);
		p += 2, q += argslen;
	    } else if (p[0] == '%' && p[1] == 'c') {
		strcpy(q, cmd);
		p += 2, q += cmdlen;
	    } else if (p[0] == '%' && p[1] == 'C') {
		strcpy(q, exec_context);
		p += 2, q += exec_context_len;
	    } else
		*q++ = *p++;
	}
    }
    log_author_cmd(session, cmd, args);
}

static int bad_nas_args(tac_session * session, struct author_data *data)
{
    int i;
    /* Check the nas args for well-formedness */
    for (i = 0; i < data->in_cnt; i++) {
	size_t k = strcspn(data->in_args[i], "=*");
	if (!k || !data->in_args[i][k]) {
	    char buf[MAX_INPUT_LINE_LEN];
	    snprintf(buf, sizeof(buf), "Illegal arg from NAS: %s", data->in_args[i]);
	    data->status = TAC_PLUS_AUTHOR_STATUS_ERROR;
	    data->admin_msg = mem_strdup(session->mem, buf);
	    report(session, LOG_ERR, ~0, "%s: %s", session->ctx->nas_address_ascii, buf);
	    return -1;
	}
    }
    return 0;
}

#define lookup_attr(T,A) (char *)RB_lookup(T,A)

static void authorize_svc(tac_session * session, enum token svc, char *svcname, char *protocol)
{
    struct author_data *data = session->author_data;
    int i, replaced = 0, added = 0, out_cnt = 0;
    char **out_args, **outp;
    enum token svc_dflt = S_unknown, attr_dflt = S_unknown;
    rb_tree_t *tree_m_a, *tree_o_a, *tree_m_av, *tree_o_av, *tree_a_a, *tree_a_av;
    rb_node_t *r;

    if (bad_nas_args(session, data)) {
	data->status = TAC_PLUS_AUTHOR_STATUS_ERROR;
	return;
    }

    tree_m_a = RB_tree_new((int (*)(const void *, const void *)) strcmp_a, NULL);
    tree_m_av = RB_tree_new((int (*)(const void *, const void *)) strcmp_av, NULL);
    tree_a_a = RB_tree_new((int (*)(const void *, const void *)) strcmp_a, NULL);
    tree_a_av = RB_tree_new((int (*)(const void *, const void *)) strcmp_av, NULL);
    tree_o_a = RB_tree_new((int (*)(const void *, const void *)) strcmp_a, NULL);
    tree_o_av = RB_tree_new((int (*)(const void *, const void *)) strcmp_av, NULL);

    switch (cfg_get_svc_attrs(session, svc, svcname, protocol, tree_m_a, tree_a_a, tree_o_a, tree_m_av, tree_a_av, tree_o_av, &svc_dflt, &attr_dflt)) {
    case S_deny:
	report(session, LOG_DEBUG, DEBUG_AUTHOR_FLAG,
	       "%s@%s: svcname=%s protocol=%s denied", session->username, session->ctx->nas_address_ascii, svcname ? svcname : "", protocol ? protocol : "");
	data->status = TAC_PLUS_AUTHOR_STATUS_FAIL;
	goto bye;
    case S_permit:
	break;
    default:
	report(session, LOG_DEBUG, DEBUG_AUTHOR_FLAG,
	       "%s@%s: svcname=%s protocol=%s not found, default is %s",
	       session->username, session->ctx->nas_address_ascii, svcname ? svcname : "", protocol ? protocol : "", codestring[svc_dflt].txt);
	switch (svc_dflt) {
	case S_permit:
	    data->status = TAC_PLUS_AUTHOR_STATUS_PASS_ADD;
	    goto bye;
	default:
	    data->status = TAC_PLUS_AUTHOR_STATUS_FAIL;
	    goto bye;
	}
    }

    /* Allocate space for in + out args */
    out_args = mem_alloc(session->mem, sizeof(char *) * (data->in_cnt + RB_count(tree_m_av) + RB_count(tree_a_av)));

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

	    if ((da = lookup_attr(tree_m_av, na))) {
		report(session, LOG_DEBUG, DEBUG_AUTHOR_FLAG, "nas:%s, svr:%s -> add %s (%c)", na, da, da, 'a');
		*outp++ = da, out_cnt++;
		continue;
	    }

	    if ((da = lookup_attr(tree_o_a, na))) {
		report(session, LOG_DEBUG, DEBUG_AUTHOR_FLAG, "nas:%s, svr:%s -> add %s (%c)", na, da, na, 'b');
		*outp++ = na, out_cnt++;
		continue;
	    }

	    /* If no attribute match exists, deny the attribute if the default
	     * is to deny */
	    if (attr_dflt != S_permit) {
		data->status = TAC_PLUS_AUTHOR_STATUS_FAIL;
		report(session, LOG_DEBUG, DEBUG_AUTHOR_FLAG, "nas:%s svr:absent/deny -> denied (c)", na);
		goto bye;
	    }
	} else {
	    char c;
	    /* NAS AV pair is optional */

	    if ((c = 'e', da = lookup_attr(tree_m_av, na)) ||
		(c = 'f', da = lookup_attr(tree_m_a, na)) || (c = 'g', da = lookup_attr(tree_o_av, na)) || (c = 'h', da = lookup_attr(tree_o_a, na))) {
		report(session, LOG_DEBUG, DEBUG_AUTHOR_FLAG, "nas:%s svr:%s -> replace with %s (%c)", na, da, da, c);
		*outp++ = da, out_cnt++, replaced++;
		continue;
	    }

	    /* If no match is found, delete the AV pair if default is deny */
	    if (attr_dflt != S_permit) {
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
	RB_search_and_delete(tree_m_av, out_args[i]);

    for (r = RB_first(tree_m_av); r; r = RB_next(r)) {
	/* Attr is required by daemon but not present. Add it */
	report(session, LOG_DEBUG, DEBUG_AUTHOR_FLAG, "nas:absent srv:%s -> add %s (k)", RB_payload(r, char *), RB_payload(r, char *));
	added++, *outp++ = RB_payload(r, char *), out_cnt++;
    }

    /*
     * After all AV pairs have been processed, for each unrequested optional
     * DAEMON AV pair ("add"), if there is no attribute match already in the
     * output list, add the AV pair (add only one AV pair for each
     * unrequested optional attribute)
     */

    for (i = 0; i < out_cnt; i++)
	RB_search_and_delete(tree_a_av, out_args[i]);

    for (r = RB_first(tree_a_av); r; r = RB_next(r)) {
	/* Attr is required by daemon but not present. Add it */
	report(session, LOG_DEBUG, DEBUG_AUTHOR_FLAG, "nas:absent srv:%s -> add %s (l)", RB_payload(r, char *), RB_payload(r, char *));
	added++, *outp++ = RB_payload(r, char *), out_cnt++;
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

  bye:
    RB_tree_delete(tree_m_a);
    RB_tree_delete(tree_a_a);
    RB_tree_delete(tree_o_a);
    RB_tree_delete(tree_m_av);
    RB_tree_delete(tree_a_av);
    RB_tree_delete(tree_o_av);
}

static void do_author(tac_session * session)
{
    struct author_data *data = session->author_data;
    char *cmd, *protocol, *svcname;
    enum token svc;

    if (!session->user && session->username[0]) {
	session->user = lookup_user(session->ctx->aaa_realm->usertable, session->username);

	if (session->user)
	    cfg_get_debug(session, &session->debug);
	if (query_mavis_info(session, do_author, PW_LOGIN))
	    return;
    }

    if (session->mavisauth_res == TAC_PLUS_AUTHEN_STATUS_ERROR) {
	report(session, LOG_DEBUG, DEBUG_AUTHOR_FLAG, "user '%s': backend failure", session->username);
	send_author_reply(session, TAC_PLUS_AUTHOR_STATUS_ERROR, NULL, NULL, 0, NULL);
	return;
    }

    if (!session->user) {
	if (session->ctx->authz_if_authc && session->authen_method != TAC_PLUS_AUTHEN_METH_TACACSPLUS && session->authen_type == TAC_PLUS_AUTHEN_TYPE_ASCII) {
	    report(session, LOG_DEBUG, DEBUG_AUTHOR_FLAG, "user '%s' not found but authenticated locally, permitted by default", session->username);
	    send_author_reply(session, TAC_PLUS_AUTHOR_STATUS_PASS_ADD, NULL, NULL, 0, NULL);
	    return;
	}
	report(session, LOG_DEBUG, DEBUG_AUTHOR_FLAG, "user '%s' not found, denied by default", session->username);
	send_author_reply(session, TAC_PLUS_AUTHOR_STATUS_FAIL, NULL, NULL, 0, NULL);
	return;
    }

    set_taglist(session);
    cfg_get_debug(session, &session->debug);

    report(session, LOG_DEBUG, DEBUG_AUTHOR_FLAG, "user '%s' found", session->username);

    svc = get_nas_svc(data, &cmd, &protocol, &svcname);

    switch (svc) {
    case S_cmd:
	authorize_cmd(session, cmd);
	break;
    case S_unknown:
	report(session, LOG_ERR, ~0, "%s: Bad service type", session->ctx->nas_address_ascii);
	data->status = TAC_PLUS_AUTHOR_STATUS_FAIL;
	data->admin_msg = "No known service/protocol in authorization request";
	break;
    default:
	authorize_svc(session, svc, svcname, protocol);
    }

    send_author_reply(session, data->status, data->server_msg, data->admin_msg, data->out_cnt, data->out_args);
}

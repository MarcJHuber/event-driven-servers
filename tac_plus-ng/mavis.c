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
#include "misc/md5crypt.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

struct mavis_data {
    const char *mavistype;
    enum pw_ix pw_ix;
    void (*mavisfn)(tac_session *);
};

struct mavis_ctx_data {
    const char *mavistype;
    void (*mavisfn)(struct context *);
};

static void mavis_lookup_final(tac_session *, av_ctx *);

static void mavis_switch(tac_session * session, av_ctx * avc, int result)
{
    if (!session->user_is_session_specific)
	session->user = NULL;	/* may be outdated */

    switch (result) {
    case MAVIS_FINAL:
	session->mavis_pending = 0;
	mavis_lookup_final(session, avc);
	if (!session->user_msg) {
	    char *comment = av_get(avc, AV_A_USER_RESPONSE);
	    if (comment) {
		size_t len = strlen(comment);
		session->user_msg = memlist_malloc(session->memlist, len + 2);
		memcpy(session->user_msg, comment, len);
		if (len && session->user_msg[len - 1] != '\n')
		    session->user_msg[len++] = '\n';
		session->user_msg_len = len;
	    }
	}
	av_free_private(avc);
	if (session->user) {
	    if (session->user->avc)
		av_free(session->user->avc);
	    session->user->avc = avc;
	}
	session->mavis_data->mavisfn(session);
	break;
    case MAVIS_TIMEOUT:
	report(session, LOG_INFO, ~0, "auth_mavis: giving up (%s)", session->username);
	io_sched_pop(session->ctx->io, session);
	session->mavis_pending = 0;
	av_free(avc);
	session->mavis_data->mavisfn(session);
	break;
    case MAVIS_DEFERRED:
	session->mavis_pending = 1;
    case MAVIS_IGNORE:
	break;
    default:
	session->mavis_pending = 0;
	av_free(avc);
	session->mavis_data->mavisfn(session);
    }
}

static void mavis_callback(tac_session * session)
{
    av_ctx *avc = NULL;
    int rc = mavis_recv(lookup_mcx(session->ctx->realm), &avc, session);
    mavis_switch(session, avc, rc);
}

void mavis_lookup(tac_session * session, void (*f)(tac_session *), const char *const type, enum pw_ix pw_ix)
{
    int result;
    av_ctx *avc;
    tac_realm *r = session->ctx->realm;
    mavis_ctx *mcx = lookup_mcx(r);

    if (!mcx) {
	f(session);
	return;
    }

    if (session->mavis_pending)
	return;

    if (r->mavis_user_acl) {
	enum token token = eval_tac_acl(session, r->mavis_user_acl);
	if (token != S_permit) {
	    report(session, LOG_ERR, ~0, "username '%s' looks bogus", session->username);
	    f(session);
	    return;
	}
    }

    if ((r->mavis_userdb != TRISTATE_YES) && !session->user) {
	f(session);
	return;
    }

    report(session, LOG_INFO, ~0, "looking for user %s in MAVIS backend", session->username);

    if (!session->mavis_data)
	session->mavis_data = memlist_malloc(session->memlist, sizeof(struct mavis_data));

    session->mavis_data->mavisfn = f;
    session->mavis_data->mavistype = type;
    session->mavis_data->pw_ix = pw_ix;

    avc = av_new((void *) mavis_callback, (void *) session);
    av_set(avc, AV_A_TYPE, AV_V_TYPE_TACPLUS);
    av_set(avc, AV_A_USER, session->username);
    av_setf(avc, AV_A_TIMESTAMP, "%d", session->session_id);
    av_set(avc, AV_A_TACTYPE, (char *) type);
    av_set(avc, AV_A_SERVERIP, session->ctx->nas_address_ascii);
    if (session->passwd_changeable)
	av_set(avc, AV_A_CALLER_CAP, ":chpw:");
    if (session->nac_address_valid)
	av_set(avc, AV_A_IPADDR, session->nac_address_ascii);
    if (r->name)
	av_set(avc, AV_A_REALM, r->name);

    if (session->password && strcmp(type, AV_V_TACTYPE_INFO))
	av_set(avc, AV_A_PASSWORD, session->password);
    if (session->password_new && !strcmp(type, AV_V_TACTYPE_CHPW))
	av_set(avc, AV_A_PASSWORD_NEW, session->password_new);

    if (!session->ctx->realm->caching_period && !strcmp(type, AV_V_TACTYPE_INFO) && session->author_data) {
	char *args, *p;
	struct author_data *data = session->author_data;
	int len = 0, cnt = data->in_cnt - 1;
	size_t *arglen = alloca(data->in_cnt * sizeof(size_t));
	for (int i = 0; i < data->in_cnt; i++) {
	    arglen[i] = strlen(data->in_args[i]);
	    len += arglen[i] + 1;
	}
	args = alloca(len);
	p = args;
	for (int i = 0; i <= cnt; i++) {
	    memcpy(p, data->in_args[i], arglen[i]);
	    p += arglen[i];
	    *p++ = (i == cnt) ? 0 : '\n';
	}
	av_set(avc, AV_A_ARGS, args);
    }

    result = mavis_send(mcx, &avc);

    switch (result) {
    case MAVIS_DEFERRED:
	session->mavis_pending = 1;
    case MAVIS_IGNORE:
	break;
    default:
	mavis_switch(session, avc, result);
    }
}

static int parse_user_profile_multi(av_ctx * avc, struct sym *sym, tac_user * u, char *format, int attribute)
{
    int res = 0;
    char *a = av_get(avc, attribute);
    if (a)
	while (!res && *a) {
	    char *t = a;
	    for (; *t && *t != '\n'; t++);
	    res |= parse_user_profile_fmt(sym, u, format, (int) (t - a), a);
	    if (!*t)
		break;
	    a = t;
	    a++;
	}
    return res;
}

static void dump_av_pairs(tac_session * session, av_ctx * avc, char *what)
{
    if (common_data.debug & (DEBUG_MAVIS_FLAG | DEBUG_TACTRACE_FLAG)) {
	int show[] = { AV_A_USER, AV_A_DN, AV_A_TACMEMBER, AV_A_MEMBEROF, AV_A_USER_RESPONSE, AV_A_SERVERIP,
	    AV_A_IPADDR, AV_A_REALM, AV_A_TACPROFILE, AV_A_SSHKEY, AV_A_SSHKEYHASH, AV_A_SSHKEYID, AV_A_PATH,
	    AV_A_UID, AV_A_GID, AV_A_HOME, AV_A_ROOT, AV_A_SHELL, AV_A_GIDS, AV_A_PASSWORD_MUSTCHANGE, AV_A_ARGS,
	    AV_A_RARGS, AV_A_VERDICT, AV_A_IDENTITY_SOURCE, AV_A_CUSTOM_0, AV_A_CUSTOM_1, AV_A_CUSTOM_2, AV_A_CUSTOM_3, -1
	};
	report(session, LOG_DEBUG, ~0, "%s found by MAVIS backend, av pairs:", what);
	for (int i = 0; show[i] > -1; i++)
	    if (avc->arr[show[i]])
		report_string(session, LOG_DEBUG, DEBUG_MAVIS_FLAG | DEBUG_TACTRACE_FLAG, av_char[show[i]].name, avc->arr[show[i]],
			      strlen(avc->arr[show[i]]));
    }
}

static void mavis_lookup_final(tac_session * session, av_ctx * avc)
{
    char *t, *result = NULL;
    tac_realm *r = session->ctx->realm;

    session->mavisauth_res = 0;

    if ((t = av_get(avc, AV_A_TYPE)) && !strcmp(t, AV_V_TYPE_TACPLUS) &&	//
	(t = av_get(avc, AV_A_TACTYPE)) && !strcmp(t, session->mavis_data->mavistype) &&	//
	(t = av_get(avc, AV_A_USER)) && !strcmp(t, session->username) &&	//
	(t = av_get(avc, AV_A_TIMESTAMP)) && (atoi(t) == session->session_id) &&	//#
	(result = av_get(avc, AV_A_RESULT)) && !strcmp(result, AV_V_RESULT_OK)) {

	tac_user *u = lookup_user(session);

	if (u)
	    r = u->realm;

	if ((r->mavis_userdb == TRISTATE_YES) && (!u || u->dynamic)) {
	    char *verdict = av_get(avc, AV_A_VERDICT);
	    if (verdict && !session->ctx->realm->caching_period && !strcmp(verdict, AV_V_BOOL_TRUE))
		session->authorized = 1;

	    dump_av_pairs(session, avc, "user");

	    if (!u || u->dynamic) {
		struct sym sym = { 0 };

		sym.filename = session->username;
		sym.line = 1;
		sym.flag_prohibit_include = 1;

		if (!r->caching_period && session->user) {
		    free_user(session->user);
		    session->user = NULL;
		}

		u = new_user(session->username, S_mavis, r);
		tac_realm *rf = r;
		while (rf) {
		    if (rf->usertable) {
			rb_node_t *rbn = RB_search(rf->usertable, u);
			if (rbn) {
			    tac_user *uf = RB_payload(rbn, tac_user *);
			    if (uf->fallback_only) {
				free_user(u);
				report(session, LOG_DEBUG, DEBUG_AUTHEN_FLAG, "Not in emergency mode, ignoring user %s", uf->name);
				return;
			    } else {
				RB_delete(rf->usertable, rbn);
				break;
			    }
			}
		    }
		    rf = rf->parent;
		}

		u->dynamic = io_now.tv_sec + r->caching_period;

		if (parse_user_profile_multi(avc, &sym, u, "{ member = %.*s }", AV_A_TACMEMBER) ||
		    parse_user_profile_multi(avc, &sym, u, "{ ssh-key = %.*s }", AV_A_SSHKEY) ||
		    parse_user_profile_multi(avc, &sym, u, "{ ssh-key-hash = %.*s }", AV_A_SSHKEYHASH) ||
		    parse_user_profile_multi(avc, &sym, u, "{ ssh-key-id = %.*s }", AV_A_SSHKEYID) ||
		    parse_user_profile_multi(avc, &sym, u, "%.*s", AV_A_TACPROFILE)
		    ) {

		    free_user(u);
		    session->user = NULL;
		    session->mavisauth_res = TAC_PLUS_AUTHEN_STATUS_FAIL;

		    static struct log_item *li_mavis_parse_error = NULL;
		    if (!li_mavis_parse_error)
			li_mavis_parse_error = parse_log_format_inline(session->ctx->host->user_messages[UM_MAVIS_PARSE_ERROR], __FILE__, __LINE__);
		    session->user_msg = eval_log_format(session, session->ctx, NULL, li_mavis_parse_error, io_now.tv_sec, &session->user_msg_len);
		    return;
		}

		session->user = u;

		if (strcmp(session->mavis_data->mavistype, AV_V_TACTYPE_INFO) && u->passwd[session->mavis_data->pw_ix])
		    switch (session->mavis_data->pw_ix) {
		    case PW_PAP:
			if (u->passwd[session->mavis_data->pw_ix]->type == S_login)
			    u->passwd[session->mavis_data->pw_ix]->type = u->passwd[PW_LOGIN]->type;
		    case PW_LOGIN:
			if (u->passwd[session->mavis_data->pw_ix]->type != S_mavis) {
			    /* Authenticated via backend, but the profile tells otherwise */
			    session->mavisauth_res = TAC_PLUS_AUTHEN_STATUS_FAIL;
			    result = AV_V_RESULT_FAIL;
			    report(session, LOG_ERR, ~0, "profile for user %s conflicts with MAVIS authentication", session->username);
			    report(session, LOG_ERR, ~0,
				   "('%s backend = mavis' at realm or global level or "
				   "'password %s = mavis' in the user profile may be required)",
				   session->mavis_data->pw_ix == PW_PAP ? "pap" : "login", session->mavis_data->pw_ix == PW_PAP ? "pap" : "login");
			}
		    default:;
		    }

		if (r->caching_period) {
		    if (!r->usertable)
			r->usertable = RB_tree_new(compare_name, (void (*)(void *)) free_user);
		    RB_insert(r->usertable, u);
		} else
		    session->user_is_session_specific = 1;

		if (strcmp(result, AV_V_RESULT_OK)) {
		    report(session, LOG_INFO, ~0, "result for user %s is %s", session->username, result);
		    return;
		}
	    }
	}

	if (u->dynamic)
	    u->dynamic = io_now.tv_sec + r->caching_period;

	session->passwd_mustchange = av_get(avc, AV_A_PASSWORD_MUSTCHANGE) ? 1 : 0;
	// password changes are supported for ASCII login anc CHPASS only
	if (session->passwd_mustchange && !session->passwd_changeable) {
	    session->passwd_mustchange = 0;
	    av_set(avc, AV_A_RESULT, AV_V_RESULT_FAIL);
	}

	t = av_get(avc, AV_A_PASSWORD_EXPIRY);
	if (t)
	    session->password_expiry = (time_t) strtol(t, NULL, 10);

	u->passwd_oneshot = ((r->mavis_noauthcache == TRISTATE_YES) || av_get(avc, AV_A_PASSWORD_ONESHOT) || session->passwd_mustchange) ? 1 : 0;

	if (!strcmp(session->mavis_data->mavistype, AV_V_TACTYPE_CHAL)) {
	    char *chal = av_get(avc, AV_A_CHALLENGE);
	    if (chal) {
		u->chalresp = TRISTATE_YES;
		// memlist_free(session->memlist, &session->challenge);
		session->challenge = memlist_strdup(session->memlist, chal);
	    } else
		u->chalresp = TRISTATE_NO;
	    return;
	}

	if (strcmp(session->mavis_data->mavistype, AV_V_TACTYPE_INFO)) {
	    session->mavisauth_res = TAC_PLUS_AUTHEN_STATUS_PASS;
	    if ((TRISTATE_YES != u->chalresp) && session->password && !u->passwd_oneshot) {
		char *pass = session->password_new ? session->password_new : session->password;
#if 1
		char *crypt, salt[13];
		salt[0] = '$';
		salt[1] = '1';
		salt[2] = '$';
		for (int i = 3; i < 11; i++)
		    salt[i] = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"[random() % 64];
		salt[11] = '$';
		salt[12] = 0;
		crypt = md5crypt(pass, salt);
		u->passwd[PW_MAVIS] = memlist_malloc(u->memlist, sizeof(struct pwdat) + strlen(crypt));
		strcpy(u->passwd[PW_MAVIS]->value, crypt);
		u->passwd[PW_MAVIS]->type = S_crypt;
#else
		u->passwd[PW_MAVIS] = memlist_malloc(u->memlist, sizeof(struct pwdat) + strlen(pass));
		strcpy(u->passwd[PW_MAVIS]->value, pass);
		u->passwd[PW_MAVIS]->type = S_clear;
#endif
		u->passwd[session->mavis_data->pw_ix] = u->passwd[PW_MAVIS];
	    }
	}
    } else if (result && !strcmp(result, AV_V_RESULT_ERROR)) {
	session->mavisauth_res = TAC_PLUS_AUTHEN_STATUS_ERROR;
	r->last_backend_failure = io_now.tv_sec;
	while (r && session->mavisauth_res) {
	    if (r->usertable) {
		tac_user u;
		u.name = session->username;
		u.name_len = strlen(u.name);
		rb_node_t *rbn = RB_search(r->usertable, &u);
		if (rbn) {
		    tac_user *uf = RB_payload(rbn, tac_user *);
		    if (uf->fallback_only) {
			report(session, LOG_DEBUG, DEBUG_AUTHEN_FLAG, "Entering emergency mode");
			session->mavisauth_res = 0;
			av_set(avc, AV_A_USER_RESPONSE, NULL);
		    }
		}
	    }
	    r = r->parent;
	}
    } else if (result && !strcmp(result, AV_V_RESULT_FAIL)) {
	session->mavisauth_res = TAC_PLUS_AUTHEN_STATUS_FAIL;
    }
    if (result)
	report(session, LOG_INFO, ~0, "result for user %s is %s", session->username, result);
}

static void mavis_ctx_lookup_final(struct context *, av_ctx *);

static void mavis_ctx_switch(struct context *ctx, av_ctx * avc, int result)
{
    switch (result) {
    case MAVIS_FINAL:
	ctx->mavis_pending = 0;
	mavis_ctx_lookup_final(ctx, avc);
	ctx->mavis_data->mavisfn(ctx);
	break;
    case MAVIS_TIMEOUT:
	// report(session, LOG_INFO, ~0, "auth_mavis: giving up (%s)", session->username);
	io_sched_pop(ctx->io, ctx);
	ctx->mavis_pending = 0;
	av_free(avc);
	ctx->mavis_data->mavisfn(ctx);
	break;
    case MAVIS_DEFERRED:
	ctx->mavis_pending = 1;
    case MAVIS_IGNORE:
	break;
    default:
	ctx->mavis_pending = 0;
	av_free(avc);
	ctx->mavis_data->mavisfn(ctx);
    }
}

static void mavis_ctx_callback(struct context *ctx)
{
    av_ctx *avc = NULL;
    int rc = mavis_recv(lookup_mcx(ctx->realm), &avc, ctx);
    mavis_ctx_switch(ctx, avc, rc);
}

void mavis_ctx_lookup(struct context *ctx, void (*f)(struct context *), const char *const type)
{
    mavis_ctx *mcx = lookup_mcx(ctx->realm);
    if (!mcx) {
	f(ctx);
	return;
    }
    if (ctx->mavis_pending)
	return;

    tac_session session = {.ctx = ctx };
    report(&session, LOG_INFO, ~0, "looking for host %s in MAVIS backend", ctx->nas_address_ascii);

    if (!ctx->mavis_data)
	ctx->mavis_data = mempool_malloc(ctx->pool, sizeof(struct mavis_data));

    ctx->mavis_data->mavisfn = f;
    ctx->mavis_data->mavistype = type;

    av_ctx *avc = av_new((void *) mavis_ctx_callback, (void *) ctx);
    av_set(avc, AV_A_TYPE, AV_V_TYPE_TACPLUS);
    av_set(avc, AV_A_USER, ctx->nas_address_ascii);
    av_set(avc, AV_A_TACTYPE, (char *) type);	// "HOST"
    av_set(avc, AV_A_REALM, ctx->realm->name);

    int result = mavis_send(mcx, &avc);
    switch (result) {
    case MAVIS_DEFERRED:
	ctx->mavis_pending = 1;
    case MAVIS_IGNORE:
	break;
    default:
	mavis_ctx_switch(ctx, avc, result);
    }
}

static void mavis_ctx_lookup_final(struct context *ctx, av_ctx * avc)
{
    char *t, *result = NULL;
    tac_session session = {.ctx = ctx };
    ctx->mavis_result = S_deny;
    if ((t = av_get(avc, AV_A_TYPE)) && !strcmp(t, AV_V_TYPE_TACPLUS) &&	//
	(t = av_get(avc, AV_A_TACTYPE)) && !strcmp(t, ctx->mavis_data->mavistype) &&	//
	(t = av_get(avc, AV_A_USER)) && !strcmp(t, ctx->nas_address_ascii) &&	//
	(result = av_get(avc, AV_A_RESULT)) && !strcmp(result, AV_V_RESULT_OK)) {

	char *profile = av_get(avc, AV_A_TACPROFILE);
	if (profile) {
	    struct memlist *memlist = memlist_create();
	    tac_host *h = memlist_malloc(memlist, sizeof(tac_host));
	    h->memlist = memlist;

	    struct sym sym = { 0 };
	    sym.filename = ctx->nas_address_ascii;
	    sym.line = 1;
	    sym.flag_prohibit_include = 1;
	    sym.in = sym.tin = profile;
	    sym.len = sym.tlen = strlen(profile);
	    parse_host_profile(&sym, ctx->realm, h);
	    h->parent = ctx->host;
	    if (!h->name) {
		h->name = ctx->host->name;
		h->name_len = ctx->host->name_len;
	    }
	    complete_host(h);
	    ctx->host = h;
	}
	ctx->mavis_result = S_permit;
	dump_av_pairs(&session, avc, "host");
    }
    if (result)
	report(&session, LOG_INFO, ~0, "result for host %s is %s", ctx->nas_address_ascii, result);
}

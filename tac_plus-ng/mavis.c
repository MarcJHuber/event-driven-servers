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

struct mavis_data {
    char *mavistype;
    enum pw_ix pw_ix;
    void (*mavisfn)(tac_session *);
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
		strncpy(session->user_msg, comment, len);
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

void mavis_lookup(tac_session * session, void (*f)(tac_session *), char *type, enum pw_ix pw_ix)
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
    av_set(avc, AV_A_TACTYPE, type);
    av_set(avc, AV_A_SERVERIP, session->ctx->nas_address_ascii);
    if (session->nac_address_valid)
	av_set(avc, AV_A_IPADDR, session->nac_address_ascii);
    if (r->name)
	av_set(avc, AV_A_REALM, r->name);

    if (session->password && strcmp(type, AV_V_TACTYPE_INFO))
	av_set(avc, AV_A_PASSWORD, session->password);
    if (session->password_new && !strcmp(type, AV_V_TACTYPE_CHPW))
	av_set(avc, AV_A_PASSWORD_NEW, session->password_new);

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

static void mavis_lookup_final(tac_session * session, av_ctx * avc)
{
    char *t, *result = NULL;
    tac_realm *r = session->ctx->realm;

    session->mavisauth_res = TAC_PLUS_AUTHEN_STATUS_FAIL;

    if ((t = av_get(avc, AV_A_TYPE)) && !strcmp(t, AV_V_TYPE_TACPLUS) &&
	(t = av_get(avc, AV_A_USER)) && !strcmp(t, session->username) &&
	(t = av_get(avc, AV_A_TIMESTAMP)) && (atoi(t) == session->session_id) && (result = av_get(avc, AV_A_RESULT)) && !strcmp(result, AV_V_RESULT_OK)) {
	struct pwdat **pp = NULL;

	tac_user *u = lookup_user(session->username, r);

	if (strcmp(session->mavis_data->mavistype, AV_V_TACTYPE_INFO))
	    session->mavisauth_res_valid = 1;
	if (u)
	    r = u->realm;

	if ((r->mavis_userdb == TRISTATE_YES) && (!u || u->dynamic)) {
	    char *tacprofile = av_get(avc, AV_A_TACPROFILE);
	    char *tacmember = av_get(avc, AV_A_TACMEMBER);
#ifdef TPNG_EXPERIMENTAL
	    char *sshkeyhash = av_get(avc, AV_A_SSHKEYHASH);
	    if (sshkeyhash && !*sshkeyhash)
		sshkeyhash = NULL;
#endif
	    if (tacprofile && !*tacprofile)
		tacprofile = NULL;
	    if (tacmember && !*tacmember)
		tacmember = NULL;

	    if (common_data.debug & (DEBUG_MAVIS_FLAG | DEBUG_TACTRACE_FLAG)) {
		int i;
		report(session, LOG_INFO, ~0, "user found by MAVIS backend, av pairs:");
		for (i = 0; i < AV_A_ARRAYSIZE; i++)
		    switch (i) {
		    case AV_A_USER:
		    case AV_A_DN:
		    case AV_A_MEMBEROF:
		    case AV_A_USER_RESPONSE:
		    case AV_A_SERVERIP:
		    case AV_A_IPADDR:
		    case AV_A_REALM:
		    case AV_A_TACPROFILE:
		    case AV_A_TACMEMBER:
		    case AV_A_SSHKEYHASH:
		    case AV_A_PATH:
		    case AV_A_UID:
		    case AV_A_GID:
		    case AV_A_HOME:
		    case AV_A_ROOT:
		    case AV_A_SHELL:
		    case AV_A_GIDS:
		    case AV_A_PASSWORD_MUSTCHANGE:
			if (avc->arr[i])
			    fprintf(stderr, "  %-20s%s\n", av_char[i], avc->arr[i]);
		    default:;
		    }
	    }

	    if (!u || tacmember
#ifdef TPNG_EXPERIMENTAL
		|| sshkeyhash
#endif
		) {
		struct sym sym;

		memset(&sym, 0, sizeof(sym));
		sym.filename = session->username;
		sym.line = 1;
		sym.flag_prohibit_include = 1;

		if (!r->caching_period && session->user) {
		    free_user(session->user);
		    session->user = NULL;
		}

		u = new_user(session->username, S_mavis, r);
		if (r->usertable) {
		    rb_node_t *rbn = RB_search(r->usertable, u);
		    if (rbn)
			RB_delete(r->usertable, rbn);
		}

		u->dynamic = io_now.tv_sec + r->caching_period;

		if ((tacmember && parse_user_profile_fmt(&sym, u, "{ member = %s }", tacmember))
		    || (tacprofile && parse_user_profile_fmt(&sym, u, "%s", tacprofile))
#ifdef TPNG_EXPERIMENTAL
		    || (sshkeyhash && parse_user_profile_fmt(&sym, u, "%s", sshkeyhash))
#endif
		    ) {
		    char *errbuf = NULL;
		    time_t tt = (time_t) io_now.tv_sec;

		    free_user(u);
		    session->user = NULL;
		    session->mavisauth_res = TAC_PLUS_AUTHEN_STATUS_ERROR;
		    session->mavisauth_res_valid = 1;

#define errfmt \
"\n" \
"An error occured while parsing your user profile. Please ask your TACACS+\n" \
"administrator to have a look at the TACACS+ logs and provide the following\n" \
"information:\n" \
"\n" \
"        Host: %s\n" \
"        User: %s\n" \
"        Date: %s\n"

#define errbuf_size 1024

		    errbuf = memlist_malloc(session->memlist, errbuf_size);
		    if (errbuf_size > snprintf(errbuf, errbuf_size, errfmt, config.hostname, session->username, ctime(&tt)))
			session->user_msg = errbuf;
		    report(session, LOG_ERR, ~0, "parsing dynamic profile failed for user %s", session->username);
		    return;
		}

		parse_user_final(u);
		session->user = u;
		pp = (eval_passwd_acl(session))->passwd;

		if (strcmp(session->mavis_data->mavistype, AV_V_TACTYPE_INFO) && pp[session->mavis_data->pw_ix])
		    switch (session->mavis_data->pw_ix) {
		    case PW_PAP:
			if (pp[session->mavis_data->pw_ix]->type == S_login)
			    pp[session->mavis_data->pw_ix]->type = pp[PW_LOGIN]->type;
		    case PW_LOGIN:
			if (pp[session->mavis_data->pw_ix]->type != S_mavis) {
			    /* Authenticated via backend, but the profile tells otherwise */
			    session->mavisauth_res = TAC_PLUS_AUTHEN_STATUS_FAIL;
			    session->mavisauth_res_valid = 0;
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
			r->usertable = RB_tree_new(compare_user, (void (*)(void *)) free_user);
		    RB_insert(r->usertable, u);
		} else
		    session->user_is_session_specific = 1;
		session->user = u;

		if (strcmp(result, AV_V_RESULT_OK)) {
		    report(session, LOG_INFO, ~0, "verdict for user %s is %s", session->username, result);
		    return;
		}
	    }
	}

	session->user = u;
	if (!pp)
	    pp = (eval_passwd_acl(session))->passwd;

	if (u->dynamic)
	    u->dynamic = io_now.tv_sec + r->caching_period;

	u->passwd_oneshot = ((r->mavis_noauthcache == TRISTATE_YES) || av_get(avc, AV_A_PASSWORD_ONESHOT)) ? 1 : 0;

	session->passwd_mustchange = av_get(avc, AV_A_PASSWORD_MUSTCHANGE) ? 1 : 0;

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
	    session->mavisauth_res_valid = 1;
	    if ((TRISTATE_YES != u->chalresp) && session->password && !u->passwd_oneshot) {
		pp[PW_MAVIS] = memlist_malloc(u->memlist, sizeof(struct pwdat) + strlen(session->password_new ? session->password_new : session->password));
		strcpy(pp[PW_MAVIS]->value, session->password_new ? session->password_new : session->password);
		pp[PW_MAVIS]->type = S_clear;
	    }
	}
    } else if (result && !strcmp(result, AV_V_RESULT_ERROR)) {
	session->mavisauth_res = TAC_PLUS_AUTHEN_STATUS_ERROR;
	session->mavisauth_res_valid = 1;
	r->last_backend_failure = io_now.tv_sec;
    } else if (result && !strcmp(result, AV_V_RESULT_FAIL)) {
	session->mavisauth_res = TAC_PLUS_AUTHEN_STATUS_FAIL;
	session->mavisauth_res_valid = 1;
    }
    if (result)
	report(session, LOG_INFO, ~0, "verdict for user %s is %s", session->username, result);
}

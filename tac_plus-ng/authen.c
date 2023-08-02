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

/*
 * References: 
 * * DES adaption to OpenSSL:
 *   h**p://www.axlradius.com/tacacs/docs/TACACSClientGuide/ciscoserverdes.htm [GONE]
 * * Microsoft PPP CHAP Extensions
 *   RFC2433
 * * Microsoft MS-CHAP-V2
 *   RFC2759
 */

#include "headers.h"
#include "misc/mymd4.h"
#include "misc/mymd5.h"
#include "misc/md5crypt.h"

#if defined(WITH_CRYPTO)
#if OPENSSL_VERSION_NUMBER < 0x30000000
#include <openssl/des.h>
#include <openssl/sha.h>
#else
#include <openssl/types.h>
#include <openssl/evp.h>
#endif
#endif

static const char rcsid[] __attribute__((used)) = "$Id$";

struct authen_data {
    u_char *data;
    size_t data_len;
    char *msg;
    size_t msg_len;
    int iterations;
    void (*authfn)(tac_session *);
};

static struct log_item *li_user_access_verification = NULL;
static struct log_item *li_username = NULL;
static struct log_item *li_password = NULL;
static struct log_item *li_response = NULL;
static struct log_item *li_permission_denied = NULL;
static struct log_item *li_password_old = NULL;
static struct log_item *li_password_new = NULL;
static struct log_item *li_password_abort = NULL;
static struct log_item *li_password_again = NULL;
static struct log_item *li_password_nomatch = NULL;
static struct log_item *li_enable_password = NULL;
static struct log_item *li_password_minreq = NULL;
static struct log_item *li_password_change_dialog = NULL;
static struct log_item *li_motd_dflt = NULL;
static struct log_item *li_change_password = NULL;
static struct log_item *li_password_incorrect_retry = NULL;
static struct log_item *li_password_incorrect = NULL;
static struct log_item *li_response_incorrect = NULL;
static struct log_item *li_account_expires = NULL;

struct hint_struct {
    char *plain;
    char *msgid;
    size_t plain_len;
    size_t msgid_len;
};

static struct hint_struct hints[hint_max] = {
    { "failed", "AUTHCFAIL", 0, 0 },
    { "failed (denied)", "AUTHCFAIL-DENY", 0, 0 },
    { "failed (password not set)", "AUTHCFAIL-NOPASS", 0, 0 },
    { "failed (expired)", "AUTHCFAIL-EXPIRED", 0, 0 },
    { "failed (no such user)", "AUTHCFAIL-NOUSER", 0, 0 },
    { "succeeded", "AUTHCPASS", 0, 0 },
    { "succeeded (permitted)", "AUTHCPASS-PERMIT", 0, 0 },
    { "failed (no clear text password set)", "AUTHCFAIL-PASSWORD-NOT-TEXT", 0, 0 },
    { "failed (backend error)", "AUTHCFAIL-BACKEND", 0, 0 },
    { "denied by user profile", "AUTHCFAIL-USERPROFILE", 0, 0 },
    { "failed (retry with identical password)", "AUTHCFAIL-DENY-RETRY", 0, 0 },
    { "failed (This might be a bug, consider reporting it!)", "AUTHCFAIL-BUG", 0, 0 },
    { "aborted by request", "AUTHCFAIL-ABORT", 0, 0 },
    { "denied by ACL", "AUTHCFAIL-ACL", 0, 0 },
    { "denied (invalid challenge length)", "AUTHCFAIL-BAD-CHALLENGE-LENGTH", 0, 0 },
    { "denied (minimum password requirements not met)", "AUTHCFAIL-WEAKPASSWORD", 0, 0 },
};

static char *get_hint(tac_session * session, enum hint_enum h)
{
    if (!hints[0].plain_len) {
	int i;
	for (i = 0; i < hint_max; i++) {
	    hints[i].plain_len = strlen(hints[i].plain);
	    hints[i].msgid_len = strlen(hints[i].msgid);
	}
    }
    if (session->user_msg) {
	size_t n = hints[h].plain_len + strlen(session->user_msg) + 20;
	char *t, *hint;
	hint = memlist_malloc(session->memlist, n);
	strcpy(hint, hints[h].plain);
	strcat(hint, " [");
	strcat(hint, session->user_msg);
	if ((t = strchr(hint, '\n')))
	    strcpy(t, "]");
	else
	    strcat(hint, "]");
	return hint;
    }
    return hints[h].plain;
}

static void report_auth(tac_session * session, char *what, enum hint_enum hint, int res)
{
    char *realm = alloca(session->ctx->realm->name_len + 40);
    char *hint_augmented;
    tac_realm *r = session->ctx->realm;
    time_t sec = io_now.tv_sec;

    if (res == TAC_PLUS_AUTHEN_STATUS_PASS) {
	session->result = codestring[S_permit];
	session->result_len = codestring_len[S_permit];
    } else {
	session->result = codestring[S_deny];
	session->result_len = codestring_len[S_deny];
    }

    if (r == config.default_realm)
	*realm = 0;
    else {
	strcpy(realm, " (realm: ");
	strcat(realm, session->ctx->realm->name);
	strcat(realm, ")");
    }

    hint_augmented = get_hint(session, hint);

    report(session, LOG_INFO, ~0,
	   "%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
	   what,
	   session->username[0] ? " for '" : "", session->username,
	   session->username[0] ? "'" : "", realm,
	   session->nac_address_ascii[0] ? " from " : "",
	   session->nac_address_ascii, session->nas_port[0] ? " on " : "", session->nas_port,
	   hint_augmented ? " " : "", hint_augmented, session->profile ? " (profile=" : "", session->profile ? session->profile->name : "",
	   session->profile ? ")" : "");

    session->msgid = hints[hint].msgid;
    session->msgid_len = hints[hint].msgid_len;
    session->action = what;
    session->action_len = strlen(what);
    session->hint = hint_augmented;
    session->hint_len = strlen(hint_augmented);

    log_exec(session, session->ctx, S_authentication, sec);
}

static int password_requirements_failed(tac_session * session, char *what)
{
    tac_realm *r = session->ctx->realm;

    if (r->password_acl) {
	enum token token;
	u_int debug = session->debug;
	if (!(session->debug & DEBUG_USERINPUT_FLAG))
	    session->debug = 0;
	token = eval_tac_acl(session, r->password_acl);
	session->debug = debug;
	if (token != S_permit) {
	    report(session, LOG_ERR, ~0, "password doesn't meet minimum requirements");
	    report_auth(session, what, hint_weak_password, TAC_PLUS_AUTHEN_STATUS_FAIL);
	    send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_FAIL,
			      eval_log_format(session, session->ctx, NULL, li_password_minreq, io_now.tv_sec, NULL), 0, NULL, 0, 0);
	    return -1;
	}
    }
    return 0;
}

static int user_invalid(tac_user * user, enum hint_enum *hint)
{
    int res = (user->valid_from && user->valid_from > io_now.tv_sec) || (user->valid_until && user->valid_until <= io_now.tv_sec);
    if (res && hint)
	*hint = hint_expired;
    return res ? TAC_PLUS_AUTHEN_STATUS_FAIL : TAC_PLUS_AUTHEN_STATUS_PASS;
}

static int compare_pwdat(struct pwdat *a, char *b, enum hint_enum *hint)
{
    int res = -1;

    switch (a->type) {
    case S_clear:
	if (b)
	    res = strcmp(a->value, b);
	break;
    case S_crypt:
	if (b) {
	    if (a->value[0] == '$' && a->value[1] == '1' && a->value[2] == '$')
		res = strcmp(a->value, md5crypt(b, a->value));
	    else
		res = strcmp(a->value, crypt(b, a->value));
	}
	break;
    case S_permit:
	*hint = hint_permitted;
	return TAC_PLUS_AUTHEN_STATUS_PASS;
    case S_deny:
	*hint = hint_denied;
	return TAC_PLUS_AUTHEN_STATUS_FAIL;
    case S_unknown:
	*hint = hint_nopass;
	return TAC_PLUS_AUTHEN_STATUS_FAIL;
    default:
	*hint = hint_bug;
	return TAC_PLUS_AUTHEN_STATUS_FAIL;
    }

    if (res) {
	*hint = hint_failed;
	return TAC_PLUS_AUTHEN_STATUS_FAIL;
    }

    *hint = hint_succeeded;
    return TAC_PLUS_AUTHEN_STATUS_PASS;
}

static enum token lookup_and_set_user(tac_session * session)
{
    enum token res = S_unknown;
    tac_host *h = session->ctx->host;
    while (res != S_permit && res != S_deny && h) {
	if (h->action) {
	    res = tac_script_eval_r(session, h->action);
	    switch (res) {
	    case S_deny:
		report(session, LOG_DEBUG, DEBUG_AUTHEN_FLAG, "user %s realm %s denied by ACL", session->username, session->ctx->realm->name);
		report_auth(session, "session", hint_denied_by_acl, S_deny);
		return S_deny;
	    case S_permit:
		break;
	    default:
		break;
	    }
	}
	h = h->parent;
    }

    tac_rewrite_user(session, NULL);
    report(session, LOG_DEBUG, DEBUG_AUTHEN_FLAG, "looking for user %s realm %s", session->username, session->ctx->realm->name);
    if (!session->user_is_session_specific) {
	session->user = lookup_user(session->username, session->ctx->realm);
    }
    if (session->user && session->user->rewritten_only && !session->username_rewritten) {
	report(session, LOG_DEBUG, DEBUG_AUTHEN_FLAG, "Login for user %s is prohibited", session->user->name);
	if (session->user_is_session_specific)
	    free_user(session->user);
	session->user = NULL;
	res = S_deny;
    } else if (session->user && session->user->fallback_only && ((session->ctx->host->authfallback != TRISTATE_YES)
								 || !session->ctx->realm->last_backend_failure
								 || (session->ctx->realm->last_backend_failure +
								     session->ctx->realm->backend_failure_period < io_now.tv_sec))) {
	report(session, LOG_DEBUG, DEBUG_AUTHEN_FLAG, "Not in emergency mode, ignoring user %s", session->user->name);
	if (session->user_is_session_specific)
	    free_user(session->user);
	session->user = NULL;
	res = S_deny;
    }

    if (session->user) {
	session->debug |= session->user->debug;
	if (session->profile)
	    session->debug |= session->profile->debug;
	res = S_permit;
    }
    report(session, LOG_DEBUG, DEBUG_AUTHEN_FLAG, "user lookup %s", (res == S_permit) ? "succeded" : "failed");
    return res;
}

static int query_mavis_auth_login(tac_session * session, void (*f)(tac_session *), enum pw_ix pw_ix)
{
    int res = !session->flag_mavis_auth
	&&( (!session->user &&(session->ctx->realm->mavis_login == TRISTATE_YES) &&(session->ctx->realm->mavis_login_prefetch != TRISTATE_YES))
	   ||(session->user && pw_ix == PW_MAVIS));
    session->flag_mavis_auth = 1;
    if (res)
	mavis_lookup(session, f, AV_V_TACTYPE_AUTH, PW_LOGIN);
    return res;
}

static int query_mavis_info_login(tac_session * session, void (*f)(tac_session *))
{
    int res = !session->flag_mavis_info && !session->user &&(session->ctx->realm->mavis_login_prefetch == TRISTATE_YES);
    session->flag_mavis_info = 1;
    if (res)
	mavis_lookup(session, f, AV_V_TACTYPE_INFO, PW_LOGIN);
    return res;
}

int query_mavis_info(tac_session * session, void (*f)(tac_session *), enum pw_ix pw_ix)
{
    int res = !session->flag_mavis_info && !session->user;
    session->flag_mavis_info = 1;
    if (res)
	mavis_lookup(session, f, AV_V_TACTYPE_INFO, pw_ix);
    return res;
}

static int query_mavis_auth_pap(tac_session * session, void (*f)(tac_session *), enum pw_ix pw_ix)
{
    int res = !session->flag_mavis_auth &&
	( (!session->user &&(session->ctx->realm->mavis_pap == TRISTATE_YES) &&(session->ctx->realm->mavis_pap_prefetch != TRISTATE_YES))
	 ||(session->user && pw_ix == PW_MAVIS));
    session->flag_mavis_auth = 1;
    if (res)
	mavis_lookup(session, f, AV_V_TACTYPE_AUTH, PW_PAP);
    return res;
}

static int query_mavis_info_pap(tac_session * session, void (*f)(tac_session *))
{
    int res = !session->user &&(session->ctx->realm->mavis_pap_prefetch == TRISTATE_YES) && !session->flag_mavis_info;
    session->flag_mavis_info = 1;
    if (res)
	mavis_lookup(session, f, AV_V_TACTYPE_INFO, PW_PAP);
    return res;
}

static void do_chap(tac_session * session)
{
    int res = TAC_PLUS_AUTHEN_STATUS_FAIL;
    enum hint_enum hint = hint_nosuchuser;

    if (S_deny == lookup_and_set_user(session)) {
	report_auth(session, "chap login", hint_denied_by_acl, res);
	send_authen_reply(session, res, NULL, 0, NULL, 0, 0);
	return;
    }

    if (query_mavis_info(session, do_chap, PW_CHAP))
	return;

    if (session->user) {
	res = user_invalid(session->user, &hint);
	if (res == TAC_PLUS_AUTHEN_STATUS_PASS) {
	    if (session->user->passwd[PW_CHAP]->type != S_clear) {
		hint = hint_no_cleartext;
		res = TAC_PLUS_AUTHEN_STATUS_FAIL;
	    } else if (session->authen_data->data_len - MD5_LEN > 0) {
		u_char digest[MD5_LEN];
		myMD5_CTX mdcontext;

		myMD5Init(&mdcontext);
		myMD5Update(&mdcontext, session->authen_data->data, (size_t) 1);
		myMD5Update(&mdcontext, (u_char *) session->user->passwd[PW_CHAP]->value, strlen(session->user->passwd[PW_CHAP]->value));
		myMD5Update(&mdcontext, session->authen_data->data + 1, (size_t) (session->authen_data->data_len - 1 - MD5_LEN));
		myMD5Final(digest, &mdcontext);

		if (memcmp(digest, session->authen_data->data + session->authen_data->data_len - MD5_LEN, (size_t) MD5_LEN)) {
		    res = TAC_PLUS_AUTHEN_STATUS_FAIL;
		    hint = hint_failed;
		} else {
		    res = TAC_PLUS_AUTHEN_STATUS_PASS;
		    hint = hint_succeeded;
		}
	    }
	}
    }

    report_auth(session, "chap login", hint, res);

    send_authen_reply(session, res, NULL, 0, NULL, 0, 0);
}

static int check_access(tac_session * session, struct pwdat *pwdat, char *passwd, enum hint_enum *hint, char **resp)
{
    int res = TAC_PLUS_AUTHEN_STATUS_FAIL;

    if (session->user) {
	if (session->mavisauth_res_valid) {
	    res = session->mavisauth_res;
	    switch (res) {
	    case TAC_PLUS_AUTHEN_STATUS_PASS:
		*hint = hint_succeeded;
		break;
	    case TAC_PLUS_AUTHEN_STATUS_ERROR:
		*hint = hint_backend_error;
		break;
	    default:
		*hint = hint_failed;
		break;
	    }
	    session->mavisauth_res = TAC_PLUS_AUTHEN_STATUS_FAIL;
	} else if (pwdat)
	    res = compare_pwdat(pwdat, passwd, hint);

	if (!session->authorized && (S_permit != eval_ruleset(session, session->ctx->realm))) {
	    res = TAC_PLUS_AUTHEN_STATUS_FAIL;
	    *hint = hint_denied_by_acl;
	}

	session->password_bad = NULL;
	if (res == TAC_PLUS_AUTHEN_STATUS_PASS)
	    res = user_invalid(session->user, hint);

	if (res != TAC_PLUS_AUTHEN_STATUS_PASS) {
	    if (session->ctx->host->reject_banner)
		*resp = eval_log_format(session, session->ctx, NULL, session->ctx->host->reject_banner, io_now.tv_sec, NULL);
	    session->password_bad = session->password;
	    session->password = NULL;
	}
    } else if (session->mavisauth_res_valid && session->mavisauth_res == TAC_PLUS_AUTHEN_STATUS_FAIL)
	*hint = hint_failed;

    if (!*resp)
	*resp = session->user_msg;
    return res;
}

static void set_pwdat(tac_session * session, struct pwdat **pwdat, enum pw_ix *pw_ix)
{
    if (session->user) {
	*pwdat = session->user->passwd[*pw_ix];
	if ((*pwdat)->type == S_login) {
	    *pw_ix = PW_LOGIN;
	    *pwdat = session->user->passwd[*pw_ix];
	}
	if ((*pwdat)->type == S_mavis) {
	    *pw_ix = PW_MAVIS;
	    *pwdat = session->user->passwd[*pw_ix];
	}
    } else
	*pwdat = NULL;
}

static char *set_welcome_banner(tac_session * session, struct log_item *fmt_dflt)
{
    struct log_item *fmt;

    if (session->welcome_banner)
	return session->msg;

    fmt = ((session->ctx->host->authfallback != TRISTATE_YES)
	   || !session->ctx->host->welcome_banner_fallback
	   || !session->ctx->realm->last_backend_failure
	   || (session->ctx->realm->last_backend_failure + session->ctx->realm->backend_failure_period < io_now.tv_sec))
	? session->ctx->host->welcome_banner : session->ctx->host->welcome_banner_fallback;

    if (!fmt)
	fmt = fmt_dflt;

    if (fmt)
	session->welcome_banner = eval_log_format(session, session->ctx, NULL, fmt, io_now.tv_sec, NULL);
    else
	session->welcome_banner = "";

    return session->welcome_banner;
}

static char *set_motd_banner(tac_session * session)
{
    struct log_item *fmt = session->ctx->host->motd;

    if (!fmt)
	fmt = li_motd_dflt;

    if (session->motd || (session->user->hushlogin == TRISTATE_YES)
	|| (session->user->hushlogin == TRISTATE_DUNNO && session->profile && session->profile->hushlogin == TRISTATE_YES)) {
	session->motd = session->user_msg;
	return NULL;
    }

    session->motd = eval_log_format(session, session->ctx, NULL, fmt, io_now.tv_sec, NULL);
    return session->motd;
}

static void do_chpass(tac_session * session)
{
    enum pw_ix pw_ix = PW_LOGIN;
    int res = TAC_PLUS_AUTHEN_STATUS_FAIL;
    enum hint_enum hint = hint_nosuchuser;
    char *resp = NULL;
    struct pwdat *pwdat = NULL;

    if (!session->username[0] && session->authen_data->msg) {
	// memlist_free(session->pool, &session->username);
	session->username = session->authen_data->msg;
	session->username_len = session->authen_data->msg_len;
	session->authen_data->msg = NULL;
    }
    if (!session->username[0]) {
	session->msg = eval_log_format(session, session->ctx, NULL, li_username, io_now.tv_sec, &session->msg_len);
	send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_GETUSER, set_welcome_banner(session, li_user_access_verification), 0, NULL, 0, 0);
	session->msg = NULL;
	return;
    }

    if (!session->password && session->authen_data->msg) {
	session->password = session->authen_data->msg;
	session->authen_data->msg = NULL;
	if (password_requirements_failed(session, "password change"))
	    return;
    }
    if (!session->password) {
	send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_GETDATA,
			  eval_log_format(session, session->ctx, NULL, li_password_old, io_now.tv_sec, NULL), 0, NULL, 0, TAC_PLUS_REPLY_FLAG_NOECHO);
	session->user_msg = NULL;
	return;
    }

    if (!session->password[0]) {
	send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_FAIL,
			  eval_log_format(session, session->ctx, NULL, li_password_abort, io_now.tv_sec, NULL), 0, NULL, 0, 0);
	return;
    }
    if (!session->password_new && session->authen_data->msg) {
	session->password_new = session->authen_data->msg;
	session->authen_data->msg = NULL;
	if (password_requirements_failed(session, "password change"))
	    return;
    }
    if (!session->password_new) {
	send_authen_reply(session, session->chpass ? TAC_PLUS_AUTHEN_STATUS_GETPASS : TAC_PLUS_AUTHEN_STATUS_GETDATA,
			  eval_log_format(session, session->ctx, NULL, li_password_new, io_now.tv_sec, NULL), 0, NULL, 0, TAC_PLUS_REPLY_FLAG_NOECHO);
	session->user_msg = NULL;
	return;
    }
    if (!session->password_new[0]) {
	send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_FAIL,
			  eval_log_format(session, session->ctx, NULL, li_password_abort, io_now.tv_sec, NULL), 0, NULL, 0, 0);
	return;
    }
    if (!session->authen_data->msg) {
	send_authen_reply(session, session->chpass ? TAC_PLUS_AUTHEN_STATUS_GETPASS : TAC_PLUS_AUTHEN_STATUS_GETDATA,
			  eval_log_format(session, session->ctx, NULL, li_password_again, io_now.tv_sec, NULL), 0, NULL, 0, TAC_PLUS_REPLY_FLAG_NOECHO);
	return;
    }

    if (strcmp(session->authen_data->msg, session->password_new)) {
	send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_FAIL,
			  eval_log_format(session, session->ctx, NULL, li_password_nomatch, io_now.tv_sec, NULL), 0, NULL, 0, 0);
	return;
    }

    if (S_deny == lookup_and_set_user(session)) {
	report_auth(session, "password change", hint_denied_by_acl, res);
	send_authen_reply(session, res, NULL, 0, NULL, 0, 0);
	return;
    }

    if (query_mavis_info_login(session, do_chpass))
	return;

    set_pwdat(session, &pwdat, &pw_ix);

    if (!session->flag_mavis_auth
	&& (((session->ctx->realm->mavis_login_prefetch != TRISTATE_YES) && !session->user) || (session->user && pw_ix == PW_MAVIS))) {
	session->flag_mavis_auth = 1;
	mavis_lookup(session, do_chpass, AV_V_TACTYPE_CHPW, PW_LOGIN);
	return;
    }

    res = check_access(session, pwdat, session->password_new, &hint, &resp);

    if (res == TAC_PLUS_AUTHEN_STATUS_PASS)
	session->passwd_mustchange = 0;

    report_auth(session, "password change", hint, res);

    send_authen_reply(session, res, resp ? resp : set_motd_banner(session), 0, NULL, 0, 0);
}

static void send_password_prompt(tac_session * session, enum pw_ix pw_ix, void (*f)(tac_session *))
{
    if( (session->ctx->realm->chalresp == TRISTATE_YES) &&(!session->user ||( (pw_ix == PW_MAVIS) &&(TRISTATE_NO != session->user->chalresp)))) {
	if(!session->flag_chalresp) {
	    session->flag_chalresp = 1;
	    mavis_lookup(session, f, AV_V_TACTYPE_CHAL, PW_LOGIN);
	    return;
	}
	if (session->challenge) {
	    char *chal = alloca(40 + strlen(session->challenge));
	    *chal = 0;
	    if (!session->welcome_banner || !session->welcome_banner[0])
		strncpy(chal, "\n", 2);
	    strcat(chal, session->challenge);
	    strcat(chal, "\n");
	    strcat(chal, eval_log_format(session, session->ctx, NULL, li_response, io_now.tv_sec, &session->msg_len));
	    strcat(chal, " ");
	    session->msg = chal;
	    session->msg_len = strlen(chal);
	    session->welcome_banner = set_welcome_banner(session, NULL);
	    send_authen_reply(session,
			      TAC_PLUS_AUTHEN_STATUS_GETPASS, session->welcome_banner, 0, NULL, 0,
			      (session->ctx->realm->chalresp_noecho == TRISTATE_YES) ? TAC_PLUS_REPLY_FLAG_NOECHO : 0);
	    session->msg = NULL;
	    return;
	}
    }

    session->msg = eval_log_format(session, session->ctx, NULL, li_password, io_now.tv_sec, &session->msg_len);
    session->welcome_banner = set_welcome_banner(session, li_user_access_verification);
    session->msg = NULL;

    send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_GETPASS, session->welcome_banner, 0, NULL, 0, TAC_PLUS_REPLY_FLAG_NOECHO);
}

/* enable with login password */
static void do_enable_login(tac_session * session)
{
    enum pw_ix pw_ix = PW_LOGIN;
    struct pwdat *pwdat = NULL;
    enum hint_enum hint = hint_nosuchuser;
    char *resp = eval_log_format(session, session->ctx, NULL, li_permission_denied, io_now.tv_sec, NULL);
    int res = TAC_PLUS_AUTHEN_STATUS_FAIL;
    char buf[40];

    if (S_deny == lookup_and_set_user(session)) {
	report_auth(session, "enable login", hint_denied_by_acl, res);
	send_authen_reply(session, res, NULL, 0, NULL, 0, 0);
	return;
    }

    if (query_mavis_info_login(session, do_enable_login))
	return;

    snprintf(buf, sizeof(buf), "enable %d", session->priv_lvl);

    set_pwdat(session, &pwdat, &pw_ix);

    if (session->authen_data->msg) {
	session->password = session->authen_data->msg;
	session->authen_data->msg = NULL;
	if (password_requirements_failed(session, buf))
	    return;
    }

    if (!session->password) {
	session->welcome_banner = "";
	send_password_prompt(session, pw_ix, do_enable_login);
	return;
    }

    pw_ix = PW_LOGIN;
    set_pwdat(session, &pwdat, &pw_ix);

    if (query_mavis_auth_login(session, do_enable_login, pw_ix))
	return;

    res = check_access(session, pwdat, session->password, &hint, &resp);

    report_auth(session, buf, hint, res);

    send_authen_reply(session, res, res == TAC_PLUS_AUTHEN_STATUS_PASS ? NULL : resp, 0, NULL, 0, 0);
}

static void do_enable_getuser(tac_session *);

static void do_enable_augmented(tac_session * session)
{
    enum pw_ix pw_ix = PW_LOGIN;
    struct pwdat *pwdat = NULL;
    int res = TAC_PLUS_AUTHEN_STATUS_FAIL;
    enum hint_enum hint = hint_nosuchuser;
    char *u;
    char *resp = eval_log_format(session, session->ctx, NULL, li_permission_denied, io_now.tv_sec, NULL);

    if (S_deny == lookup_and_set_user(session)) {
	report_auth(session, "enable login", hint_denied_by_acl, res);
	send_authen_reply(session, res, NULL, 0, NULL, 0, 0);
	return;
    }

    if (query_mavis_info_login(session, do_enable_augmented))
	return;

    if ((!session->enable || (session->enable->type != S_permit)) && !session->authen_data->msg) {
	send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_GETPASS,
			  eval_log_format(session, session->ctx, NULL, li_password, io_now.tv_sec, NULL), 0, NULL, 0, TAC_PLUS_REPLY_FLAG_NOECHO);
	return;
    }

    if (session->authen_data->msg) {
	u = strchr(session->authen_data->msg, ' ');
	if (u) {
	    *u++ = 0;
	    session->username = session->authen_data->msg;
	    session->username_len = session->authen_data->msg_len;
	    session->password = u;
	    session->authen_data->msg = NULL;
	    if (password_requirements_failed(session, "enable login"))
		return;
	    if (S_deny == lookup_and_set_user(session)) {
		report_auth(session, "enable login", hint_denied_by_acl, res);
		send_authen_reply(session, res, NULL, 0, NULL, 0, 0);
		return;
	    }
	}
    }

    set_pwdat(session, &pwdat, &pw_ix);

    if (session->username[0]) {
	if (query_mavis_auth_login(session, do_enable_augmented, pw_ix))
	    return;

	cfg_get_enable(session, &session->enable);

	if (session->enable) {
	    if (session->enable->type == S_login)
		res = check_access(session, pwdat, session->password, &hint, &resp);
	    else
		hint = hint_denied_profile;
	}
    }

    report_auth(session, "enable login", hint, res);

    send_authen_reply(session, res, ((res == TAC_PLUS_AUTHEN_STATUS_PASS) ? NULL : resp), 0, NULL, 0, 0);
}

static void do_enable(tac_session * session)
{
    int res = TAC_PLUS_AUTHEN_STATUS_FAIL;
    enum hint_enum hint = hint_nosuchuser;
    char buf[40];

    if ((session->ctx->host->augmented_enable == TRISTATE_YES) && (S_permit == eval_tac_acl(session, session->ctx->realm->enable_user_acl))
	) {
	session->username[0] = 0;
	session->authen_data->authfn = do_enable_augmented;
	do_enable_augmented(session);
	return;
    }

    if ((!session->username[0] || (S_permit == eval_tac_acl(session, session->ctx->realm->enable_user_acl)))
	&& !session->enable_getuser && (session->ctx->host->anon_enable == TRISTATE_NO)) {
	session->enable_getuser = 1;
	session->username[0] = 0;
	session->authen_data->authfn = do_enable_getuser;
	do_enable_getuser(session);
	return;
    }

    if (S_deny == lookup_and_set_user(session)) {
	snprintf(buf, sizeof(buf), "enable %d", session->priv_lvl);
	report_auth(session, buf, hint_denied_by_acl, res);
	send_authen_reply(session, res, NULL, 0, NULL, 0, 0);
	return;
    }
    if (query_mavis_info(session, do_enable, PW_LOGIN))
	return;


    if (!session->enable)
	cfg_get_enable(session, &session->enable);

    if (session->enable && session->enable_getuser && (session->enable->type == S_permit))
	res = TAC_PLUS_AUTHEN_STATUS_PASS;
    else {
	if (session->user && session->enable && (session->enable->type == S_login)) {
	    session->authen_data->authfn = do_enable_login;
	    session->flag_mavis_auth = 0;
	    do_enable_login(session);
	    return;
	}
	if ((!session->enable || (session->enable->type != S_permit)) && !session->authen_data->msg) {
	    send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_GETPASS,
			      eval_log_format(session, session->ctx, NULL, session->enable_getuser ? li_enable_password : li_password, io_now.tv_sec, NULL),
			      0, NULL, 0, TAC_PLUS_REPLY_FLAG_NOECHO);
	    return;
	}

	if (session->enable)
	    res = compare_pwdat(session->enable, session->authen_data->msg, &hint);
    }

    snprintf(buf, sizeof(buf), "enable %d", session->priv_lvl);

    report_auth(session, buf, hint, res);

    send_authen_reply(session, res, (res == TAC_PLUS_AUTHEN_STATUS_PASS) ? NULL :
		      eval_log_format(session, session->ctx, NULL, li_permission_denied, io_now.tv_sec, NULL), 0, NULL, 0, 0);
}

static void do_ascii_login(tac_session * session)
{
    enum pw_ix pw_ix = PW_LOGIN;
    struct pwdat *pwdat = NULL;
    enum hint_enum hint = hint_nosuchuser;
    char *resp = NULL, *m;
    int res = TAC_PLUS_AUTHEN_STATUS_FAIL;

    if (!session->username[0] && session->authen_data->msg) {
	// memlist_free(session->pool, &session->username);
	session->username = session->authen_data->msg;
	session->username_len = session->authen_data->msg_len;
	session->authen_data->msg = NULL;
    }

    if (!session->username[0]) {
	session->msg = eval_log_format(session, session->ctx, NULL, li_username, io_now.tv_sec, &session->msg_len);
	send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_GETUSER, set_welcome_banner(session, li_user_access_verification), 0, NULL, 0, 0);
	session->msg = NULL;
	return;
    }

    if (S_deny == lookup_and_set_user(session)) {
	report_auth(session, "shell login", hint_denied_by_acl, res);
	send_authen_reply(session, res, NULL, 0, NULL, 0, 0);
	return;
    }
    if (query_mavis_info_login(session, do_ascii_login))
	return;
    set_pwdat(session, &pwdat, &pw_ix);

    if (!pwdat || (pwdat->type != S_permit)) {
	if (session->authen_data->msg) {
	    session->password = session->authen_data->msg;
	    session->authen_data->msg = NULL;
	    if (password_requirements_failed(session, "shell login"))
		return;
	}

	if (!session->password) {
	    send_password_prompt(session, pw_ix, do_ascii_login);
	    return;
	}

	if ((session->ctx->realm->chpass == TRISTATE_YES) && (!session->user || ((session->user->chalresp != TRISTATE_YES) && !session->user->passwd_oneshot))
	    && (!session->password[0] && (pw_ix == PW_MAVIS || (session->ctx->realm->mavis_userdb == TRISTATE_YES)))) {
	    // memlist_free(session->memlist, &session->password);
	    session->password = NULL;
	    session->authen_data->authfn = do_chpass;
	    session->flag_mavis_auth = 0;
	    session->user_msg = eval_log_format(session, session->ctx, NULL, li_password_change_dialog, io_now.tv_sec, NULL);
	    do_chpass(session);
	    return;
	}
    }

    pw_ix = PW_LOGIN;
    set_pwdat(session, &pwdat, &pw_ix);

    if (query_mavis_auth_login(session, do_ascii_login, pw_ix))
	return;

    if (session->user && session->password && session->password_bad && !strcmp(session->password, session->password_bad)) {
	/* Safeguard against router-initiated login retries. Stops
	 * backend from prematurely locking the user's account,
	 * eventually.
	 */
	res = TAC_PLUS_AUTHEN_STATUS_FAIL;
	hint = hint_failed_password_retry;
	session->password_bad_again = 1;
    } else {
	res = check_access(session, pwdat, session->password, &hint, &resp);
	session->password_bad_again = 0;
    }

    //memlist_free(session->memlist, &session->challenge);

    report_auth(session, "shell login", hint, res);

    switch (res) {
    case TAC_PLUS_AUTHEN_STATUS_ERROR:
	send_authen_error(session, "Authentication backend failure.");
	return;
    case TAC_PLUS_AUTHEN_STATUS_PASS:
	if (session->passwd_mustchange) {
	    if (!session->user_msg)
		session->user_msg = eval_log_format(session, session->ctx, NULL, li_change_password, io_now.tv_sec, NULL);
	    session->flag_mavis_auth = 0;
	    session->authen_data->authfn = do_chpass;
	    do_chpass(session);
	    return;
	}

	if (session->user->valid_until && session->user->valid_until < io_now.tv_sec + session->ctx->realm->warning_period)
	    session->user_msg = eval_log_format(session, session->ctx, NULL, li_account_expires, io_now.tv_sec, &session->user_msg_len);

	send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_PASS, set_motd_banner(session), 0, NULL, 0, 0);
	session->user_msg = NULL;
	return;
    case TAC_PLUS_AUTHEN_STATUS_FAIL:
	if (resp) {
	    send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_FAIL, resp, 0, NULL, 0, 0);
	    return;
	}
    }

    if (++session->authen_data->iterations < session->ctx->host->authen_max_attempts) {
	m = eval_log_format(session, session->ctx, NULL,
			    (session->user && (session->user->chalresp == TRISTATE_YES)) ? li_response_incorrect : li_password_incorrect_retry,
			    io_now.tv_sec, NULL);
	session->flag_mavis_auth = 0;
	send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_GETPASS, m, 0, NULL, 0, TAC_PLUS_REPLY_FLAG_NOECHO);
    } else {
	send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_FAIL, NULL, 0, NULL, 0, 0);
    }
}

#define EAP_REQUEST     1
#define EAP_RESPONSE    2
#define EAP_SUCCESS     3
#define EAP_FAILURE     4
static int eap_step(tac_session * session __attribute__((unused)),
		    u_char * eap_in __attribute__((unused)), size_t eap_in_len __attribute__((unused)),
		    u_char * eap_out __attribute__((unused)), size_t *eap_out_len __attribute__((unused)))
{
    *eap_out_len = 4;
    eap_out[0] = EAP_FAILURE;
    eap_out[1] = 0;
    eap_out[2] = 0;
    eap_out[3] = 4;
    return eap_out[0];
}

static void do_eap(tac_session * session)
{
    int res = TAC_PLUS_AUTHEN_STATUS_FAIL;
    enum hint_enum hint = hint_nosuchuser;
    u_char eap_out[0x10000], *eap_in = NULL;
    size_t eap_out_len = 0, eap_in_len = 0;

    if (S_deny == lookup_and_set_user(session)) {
	report_auth(session, "shell login", hint_denied_by_acl, res);
	send_authen_reply(session, res, NULL, 0, NULL, 0, 0);
	return;
    }

    if (query_mavis_info_login(session, do_eap))
	return;

    if (!session->user) {
	send_authen_reply(session, res, eval_log_format(session, session->ctx, NULL, li_permission_denied, io_now.tv_sec, NULL), 0, NULL, 0, 0);
	return;
    }

    if (session->seq_no > 1) {
	eap_in = session->authen_data->data;
	eap_in_len = session->authen_data->data_len;
    } else if (!session->authen_data) {
	send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_FAIL, "EAP payload is missing", 0, NULL, 0, 0);
	return;
    }

    switch (eap_step(session, eap_in, eap_in_len, eap_out, &eap_out_len)) {
    case EAP_REQUEST:
	send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_GETDATA, NULL, 0, eap_out, eap_out_len, 0);
	return;
    case EAP_SUCCESS:
	res = TAC_PLUS_AUTHEN_STATUS_PASS;
	break;
    default:
	res = TAC_PLUS_AUTHEN_STATUS_FAIL;
	break;
    }

    report_auth(session, "shell login", hint, res);

    if (res == TAC_PLUS_AUTHEN_STATUS_PASS) {
	if (session->user->valid_until && session->user->valid_until < io_now.tv_sec + session->ctx->realm->warning_period)
	    session->user_msg = eval_log_format(session, session->ctx, NULL, li_account_expires, io_now.tv_sec, &session->user_msg_len);
	send_authen_reply(session, res, set_motd_banner(session), 0, eap_out, eap_out_len, 0);
    } else
	send_authen_reply(session, res, NULL, 0, eap_out, eap_out_len, 0);
}

static void do_enable_getuser(tac_session * session)
{
    enum pw_ix pw_ix = PW_LOGIN;
    struct pwdat *pwdat = NULL;
    enum hint_enum hint = hint_nosuchuser;
    char *resp = eval_log_format(session, session->ctx, NULL, li_password_incorrect, io_now.tv_sec, NULL);
    int res = TAC_PLUS_AUTHEN_STATUS_FAIL;

    if (!session->username[0] && session->authen_data->msg) {
	session->username = session->authen_data->msg;
	session->username_len = session->authen_data->msg_len;
	session->authen_data->msg = NULL;
    }

    if (!session->username[0]) {
	// memlist_free(session->memlist, &session->username);
	send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_GETUSER,
			  eval_log_format(session, session->ctx, NULL, li_username, io_now.tv_sec, NULL), 0, NULL, 0, 0);
	return;
    }

    if (S_deny == lookup_and_set_user(session)) {
	report_auth(session, "enforced enable login", hint_denied_by_acl, res);
	send_authen_reply(session, res, NULL, 0, NULL, 0, 0);
	return;
    }
    if (query_mavis_info_login(session, do_enable_getuser))
	return;
    set_pwdat(session, &pwdat, &pw_ix);

    if (session->authen_data->msg) {
	session->password = session->authen_data->msg;
	session->authen_data->msg = NULL;
	if (password_requirements_failed(session, "enforced enable login"))
	    return;
    }

    if (!session->password) {
	send_password_prompt(session, pw_ix, do_enable_getuser);
	return;
    }


    if (session->user) {
	pw_ix = PW_LOGIN;
	set_pwdat(session, &pwdat, &pw_ix);
    }

    if (query_mavis_auth_login(session, do_enable_getuser, pw_ix))
	return;

    res = check_access(session, pwdat, session->password, &hint, &resp);
    // memlist_free(session->memlist, &session->challenge);

    report_auth(session, "enforced enable login", hint, res);

    switch (res) {
    case TAC_PLUS_AUTHEN_STATUS_PASS:
	session->authen_data->authfn = do_enable;
	do_enable(session);
	break;
    default:
	send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_FAIL, resp, 0, NULL, 0, 0);
    }
}

#ifdef WITH_CRYPTO
static void mschap_desencrypt(u_char * clear, u_char * str __attribute__((unused)), u_char * cypher)
{
    unsigned char key[8];

    /*
     * Copy the key inserting parity bits. This is a little cryptic:
     * basicly we are inserting one bit into the stream after every 7 bits
     */

    key[0] = ((str[0] & 0xfe));
    key[1] = ((str[0] & 0x01) << 7) | ((str[1] & 0xfc) >> 1);
    key[2] = ((str[1] & 0x03) << 6) | ((str[2] & 0xf8) >> 2);
    key[3] = ((str[2] & 0x07) << 5) | ((str[3] & 0xf0) >> 3);
    key[4] = ((str[3] & 0x0f) << 4) | ((str[4] & 0xe0) >> 4);
    key[5] = ((str[4] & 0x1f) << 3) | ((str[5] & 0xc0) >> 5);
    key[6] = ((str[5] & 0x3f) << 2) | ((str[6] & 0x80) >> 6);
    key[7] = ((str[6] & 0x7f) << 1);

    /* copy clear to cypher, cause our des encrypts in place */
    memcpy(cypher, clear, (size_t) 8);

#if OPENSSL_VERSION_NUMBER < 0x30000000
    {
	struct DES_ks ks;
	memset(&ks, 0, sizeof(ks));
	DES_set_key((DES_cblock *) key, &ks);
	DES_ecb_encrypt((DES_cblock *) clear, (DES_cblock *) cypher, &ks, DES_ENCRYPT);
    }
#else
    {
	// I've no idea whether this will work, and I've a strong tendency to drop both MSCHAPv1 and MSCHAPv2 support
	int out_len = 8;
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit(ctx, EVP_des_ecb(), key, NULL);
	EVP_EncryptUpdate(ctx, cypher, &out_len, clear, 8);
	EVP_EncryptFinal(ctx, cypher, &out_len);
	EVP_CIPHER_CTX_free(ctx);
    }
#endif
}

static void mschap_deshash(u_char * clear, u_char * cypher)
{
    mschap_desencrypt((u_char *) "KGS!@#$%", clear, cypher);
}

static void mschap_lmhash(char *password, u_char * hash)
{
    u_char upassword[15];
    int i = 0;

    memset(upassword, 0, sizeof(upassword));
    for (; password[i]; i++)
	upassword[i] = (u_char) toupper((int) (password[i]));

    mschap_deshash(upassword, hash);
    mschap_deshash(upassword + 7, hash + 8);
}

static void mschap_chalresp(u_char * chal, u_char * hash, u_char * resp)
{
    u_char zhash[21];

    memset(zhash, 0, sizeof(zhash));
    memcpy(zhash, hash, (size_t) 16);

    mschap_desencrypt(chal, zhash, resp);
    mschap_desencrypt(chal, zhash + 7, resp + 8);
    mschap_desencrypt(chal, zhash + 14, resp + 16);
}

static void mschap_lmchalresp(u_char * chal, char *password, u_char * resp)
{
    u_char hash[16];

    mschap_lmhash(password, hash);
    mschap_chalresp(chal, hash, resp);
}

static void mschap_nthash(char *password, u_char * hash)
{
    myMD4_CTX context;
    int i = 0;
    size_t j = 2 * strlen(password);
    char *unicode = alloca(j);

    while (*password) {
	unicode[i++] = *password++;
	unicode[i++] = 0;
    }

    MD4Init(&context);
    MD4Update(&context, (u_char *) unicode, i);
    MD4Final(hash, &context);
}

static void mschap_ntchalresp(u_char * chal, char *password, u_char * resp)
{
    u_char hash[16];

    mschap_nthash(password, hash);
    mschap_chalresp(chal, hash, resp);
}

static void do_mschap(tac_session * session)
{
    int res = TAC_PLUS_AUTHEN_STATUS_FAIL;
    enum hint_enum hint = hint_nosuchuser;

    if (S_deny == lookup_and_set_user(session)) {
	report_auth(session, "mchap login", hint_denied_by_acl, res);
	send_authen_reply(session, res, NULL, 0, NULL, 0, 0);
	return;
    }
    if (query_mavis_info(session, do_mschap, PW_MSCHAP))
	return;

    if (session->user) {
	if (session->user->passwd[PW_MSCHAP]->type != S_clear)
	    hint = hint_no_cleartext;
	else if (session->authen_data->data_len == 1 /* PPP id */  + 8 /* challenge length */  + MSCHAP_DIGEST_LEN) {
	    u_char response[24];
	    u_char *chal = session->authen_data->data + 1;
	    u_char *resp = session->authen_data->data + session->authen_data->data_len - MSCHAP_DIGEST_LEN;
	    session->authen_data->data = NULL;

	    if (resp[48]) {
		mschap_ntchalresp(chal, session->user->passwd[PW_MSCHAP]->value, response);
		if (!memcmp(response, resp + 24, 24))
		    res = TAC_PLUS_AUTHEN_STATUS_PASS;
	    } else {
		mschap_lmchalresp(chal, session->user->passwd[PW_MSCHAP]->value, response);
		if (!memcmp(response, resp, 24))
		    res = TAC_PLUS_AUTHEN_STATUS_PASS;
	    }

	    if (res == TAC_PLUS_AUTHEN_STATUS_PASS)
		res = user_invalid(session->user, &hint);
	} else
	    hint = hint_invalid_challenge_length;
    }

    report_auth(session, "mschap login", hint, res);

    send_authen_reply(session, res, NULL, 0, NULL, 0, 0);
}

// The MSCHAPv2 support code is completely untested as of 2020-12-12 ...

static void mschapv2_chalhash(u_char * peerChal, u_char * authChal, char *user, u_char * chal)
{
    u_char md[SHA_DIGEST_LENGTH];
#if OPENSSL_VERSION_NUMBER < 0x30000000
    SHA_CTX c;
    SHA1_Init(&c);
    SHA1_Update(&c, peerChal, 16);
    SHA1_Update(&c, authChal, 16);
    SHA1_Update(&c, user, strlen(user));
    SHA1_Final(md, &c);
#else
    size_t len = strlen(user);
    u_char *d = alloca(32 + len);
    memcpy(d, peerChal, 16);
    memcpy(d + 16, authChal, 16);
    memcpy(d + 32, user, len);
    EVP_Q_digest(NULL, "SHA1", NULL, d, 32 + len, md, NULL);
#endif
    memcpy(chal, md, 8);
}

static void mschapv2_ntresp(u_char * achal, u_char * pchal, char *user, char *pass, u_char * resp)
{
    u_char challenge[8];
    u_char hash[16];
    mschapv2_chalhash(pchal, achal, user, challenge);
    mschap_nthash(pass, hash);
    mschap_chalresp(challenge, hash, resp);
}

static void do_mschapv2(tac_session * session)
{
    int res = TAC_PLUS_AUTHEN_STATUS_FAIL;
    enum hint_enum hint = hint_nosuchuser;

    if (S_deny == lookup_and_set_user(session)) {
	report_auth(session, "mchapv2 login", hint_denied_by_acl, res);
	send_authen_reply(session, res, NULL, 0, NULL, 0, 0);
	return;
    }
    if (query_mavis_info(session, do_mschapv2, PW_MSCHAP))
	return;

    if (session->user) {
	if (session->user->passwd[PW_MSCHAP]->type != S_clear)
	    hint = hint_no_cleartext;
	else if (session->authen_data->data_len == 1 /* PPP id */  + 16 /* challenge length */  + MSCHAP_DIGEST_LEN) {
	    u_char *chal = session->authen_data->data + 1;
	    u_char *resp = session->authen_data->data + session->authen_data->data_len - MSCHAP_DIGEST_LEN;
	    session->authen_data->data = NULL;
	    u_char reserved = 0;
	    u_char *r;
	    for (r = resp + 16; r < resp + 24; r++)
		reserved |= *r;
	    if (!reserved && !resp[48] /* reserved, must be zero */ ) {
		u_char response[24];

		mschapv2_ntresp(chal, resp, session->user->name, session->user->passwd[PW_MSCHAP]->value, response);
		if (!memcmp(response, resp + 24, 24))
		    res = TAC_PLUS_AUTHEN_STATUS_PASS;
	    }

	    if (res == TAC_PLUS_AUTHEN_STATUS_PASS)
		res = user_invalid(session->user, &hint);
	} else
	    hint = hint_invalid_challenge_length;
    }

    report_auth(session, "mschapv2 login", hint, res);

    send_authen_reply(session, res, NULL, 0, NULL, 0, 0);
}
#endif

static void do_login(tac_session * session)
{
    enum pw_ix pw_ix = PW_LOGIN;
    struct pwdat *pwdat = NULL;
    int res = TAC_PLUS_AUTHEN_STATUS_FAIL;
    enum hint_enum hint = hint_nosuchuser;
    char *resp = NULL;

    if (!session->password) {
	session->password = (char *) session->authen_data->data;
	session->authen_data->data = NULL;
	if (password_requirements_failed(session, "ascii login"))
	    return;
    }

    if (S_deny == lookup_and_set_user(session)) {
	report_auth(session, "ascii login", hint_denied_by_acl, res);
	send_authen_reply(session, res, NULL, 0, NULL, 0, 0);
	return;
    }
    if (query_mavis_info_login(session, do_login))
	return;
    set_pwdat(session, &pwdat, &pw_ix);

    if (query_mavis_auth_login(session, do_login, pw_ix))
	return;

    res = check_access(session, pwdat, session->password, &hint, &resp);

    report_auth(session, "ascii login", hint, res);

    send_authen_reply(session, res, resp, 0, NULL, 0, 0);
}

static void do_pap(tac_session * session)
{
    enum pw_ix pw_ix = PW_PAP;
    struct pwdat *pwdat = NULL;
    int res = TAC_PLUS_AUTHEN_STATUS_FAIL;
    enum hint_enum hint = hint_nosuchuser;
    char *resp = NULL;

    if (session->ctx->host->map_pap_to_login == TRISTATE_YES) {
	do_login(session);
	return;
    }

    //if (session->password) memlist_free(session->mempool, &session->password);
    session->password = NULL;

    if (session->version != TAC_PLUS_VER_ONE && session->seq_no == 1) {
	send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_GETPASS,
			  eval_log_format(session, session->ctx, NULL, li_password, io_now.tv_sec, NULL), 0, NULL, 0, TAC_PLUS_REPLY_FLAG_NOECHO);
	return;
    }

    if (session->version == TAC_PLUS_VER_ONE) {
	session->password = (char *) session->authen_data->data;
	session->authen_data->data = NULL;
    } else {
	session->password = (char *) session->authen_data->msg;
	session->authen_data->msg = NULL;
    }
    if (password_requirements_failed(session, "pap login"))
	return;

    if (S_deny == lookup_and_set_user(session)) {
	report_auth(session, "pap login", hint_denied_by_acl, res);
	send_authen_reply(session, res, NULL, 0, NULL, 0, 0);
	return;
    }
    if (query_mavis_info_pap(session, do_pap))
	return;
    set_pwdat(session, &pwdat, &pw_ix);

    if (query_mavis_auth_pap(session, do_pap, pw_ix))
	return;

    res = check_access(session, pwdat, session->password, &hint, &resp);

    report_auth(session, "pap login", hint, res);

    if (!resp)
	resp = session->user_msg;

    send_authen_reply(session, res, resp, 0, NULL, 0, 0);
}

// This is proof-of-concept code for SSH key validation with minor protocol changes.
// Clients just need to use TAC_PLUS_AUTHEN_TYPE_SSHKEYHASH (8) and put the ssh public
// key hash into the data field. This should be really easy to implement. The daemon
// will return the SSH key that matches the hash.
//
// The key has can easily retrieved using
//     ssh-keygen -lf ~/.ssh/id_rsa.pub
//
// OpenSSH integration is easily possible, too, via AuthorizedKeysCommand.
//
static void do_sshkeyhash(tac_session * session)
{
    int res = TAC_PLUS_AUTHEN_STATUS_FAIL;
    enum hint_enum hint = hint_nosuchuser;
    char *resp = NULL;
    char *key = NULL;

    if (S_deny == lookup_and_set_user(session)) {
	report_auth(session, "ssh-key-hash login", hint_denied_by_acl, res);
	send_authen_reply(session, res, NULL, 0, NULL, 0, 0);
	return;
    }
    if (query_mavis_info(session, do_sshkeyhash, PW_LOGIN))
	return;

    session->ssh_key_hash = (char *) session->authen_data->data;

    if (session->user && session->ssh_key_hash && *session->ssh_key_hash) {
	enum token token = validate_ssh_hash(session, session->ssh_key_hash, &key);

	if (token == S_permit) {
	    token = session->authorized ? S_permit : eval_ruleset(session, session->ctx->realm);
	    if (token == S_permit) {
		res = TAC_PLUS_AUTHEN_STATUS_PASS;
		hint = hint_permitted;
	    } else {
		hint = hint_denied_by_acl;
	    }
	} else
	    hint = hint_denied;

	if (res == TAC_PLUS_AUTHEN_STATUS_PASS) {
	    // memlist_free(session->pool, &session->password);
	    session->password = NULL;
	    if (res != TAC_PLUS_AUTHEN_STATUS_PASS && session->ctx->host->reject_banner)
		resp = eval_log_format(session, session->ctx, NULL, session->ctx->host->reject_banner, io_now.tv_sec, NULL);
	    if (res == TAC_PLUS_AUTHEN_STATUS_PASS)
		res = user_invalid(session->user, &hint);
	}
    }

    if (res == TAC_PLUS_AUTHEN_STATUS_PASS)
	hint = hint_permitted;
    report_auth(session, "ssh-key-hash login", hint, res);

    send_authen_reply(session, res, resp, 0, (u_char *) key, 0, 0);
}

// This is proof-of-concept code for SSH certificate validation with minor protocol changes.
// Clients just need to use TAC_PLUS_AUTHEN_TYPE_SSHCERTASH (9) and put the client certificate
// key-id into the data field. The daemon will return a matching AuthorizedPrincipalsFile line. 
//
// OpenSSH integration is easily possible, too, via AuthorizedPrincipalsCommand.
//

static void do_sshcerthash(tac_session * session)
{
    int res = TAC_PLUS_AUTHEN_STATUS_FAIL;
    enum hint_enum hint = hint_nosuchuser;
    char *resp = NULL;
    char *key = NULL;

    if (S_deny == lookup_and_set_user(session)) {
	report_auth(session, "ssh-cert-hash login", hint_denied_by_acl, res);
	send_authen_reply(session, res, NULL, 0, NULL, 0, 0);
	return;
    }
    if (query_mavis_info(session, do_sshcerthash, PW_LOGIN))
	return;

    session->ssh_key_id = (char *) session->authen_data->data;

    if (session->user && session->ssh_key_id && *session->ssh_key_id) {
	enum token token = validate_ssh_key_id(session);

	if (token == S_permit) {
	    token = session->authorized ? S_permit : eval_ruleset(session, session->ctx->realm);
	    if (token == S_permit) {
		res = TAC_PLUS_AUTHEN_STATUS_PASS;
		hint = hint_permitted;
	    } else {
		hint = hint_denied_by_acl;
	    }
	} else
	    hint = hint_denied;

	if (res == TAC_PLUS_AUTHEN_STATUS_PASS) {
	    // memlist_free(session->pool, &session->password);
	    session->password = NULL;
	    if (res != TAC_PLUS_AUTHEN_STATUS_PASS && session->ctx->host->reject_banner)
		resp = eval_log_format(session, session->ctx, NULL, session->ctx->host->reject_banner, io_now.tv_sec, NULL);
	    if (res == TAC_PLUS_AUTHEN_STATUS_PASS)
		res = user_invalid(session->user, &hint);
	}
    }

    if (res == TAC_PLUS_AUTHEN_STATUS_PASS)
	hint = hint_permitted;
    report_auth(session, "ssh-key-hash login", hint, res);

    send_authen_reply(session, res, resp, 0, (u_char *) key, 0, 0);
}

#ifdef WITH_DNS
static void free_reverse(void *payload, void *data __attribute__((unused)))
{
    free(((struct revmap *) payload)->name);
    free(payload);
}

void add_revmap(tac_realm * r, struct in6_addr *address, char *hostname, int ttl)
{
    while (r && !r->idc)
	r = r->parent;
    if (r) {
	struct revmap *rev;
	if (!hostname)
	    hostname = "";
	if (!r->dns_tree_ptr[1])
	    r->dns_tree_ptr[1] = radix_new(free_reverse, NULL);
	rev = radix_lookup(r->dns_tree_ptr[1], address, NULL);
	if (rev)
	    free(rev->name);
	else
	    rev = calloc(1, sizeof(struct revmap));
	rev->name = strdup(hostname);
	rev->ttl = (ttl == -1) ? -1 : io_now.tv_sec + ttl;
	radix_add(r->dns_tree_ptr[1], address, 128, rev);
    }
}

static void set_revmap_nac(tac_session * session, char *hostname, int ttl)
{
    report(session, LOG_DEBUG, DEBUG_LWRES_FLAG, "NAC revmap(%s) = %s", session->nac_address_ascii, hostname ? hostname : "(not found)");
    if (hostname)
	session->nac_dns_name = memlist_strdup(session->memlist, hostname);

    session->revmap_pending = 0;
    session->revmap_timedout = 0;

    add_revmap(session->ctx->realm, &session->nac_address, hostname, ttl);

    if (!session->ctx->revmap_pending && session->resumefn)
	resume_session(session, -1);
}
#endif

void get_revmap_nac(tac_session * session)
{
    tac_realm *r = session->ctx->realm;
    if (session->nac_address_valid) {
	while (r) {
	    int i;
	    for (i = 0; i < 3; i++) {
		if (r->dns_tree_ptr[i]) {
		    struct revmap *rev = radix_lookup(r->dns_tree_ptr[i], &session->nac_address, NULL);
		    if (rev && rev->name && rev->ttl >= io_now.tv_sec) {
			session->nac_dns_name = memlist_strdup(session->memlist, rev->name);
			session->nac_dns_name_len = strlen(session->nac_dns_name);
			report(NULL, LOG_DEBUG, DEBUG_LWRES_FLAG, "NAC revmap(%s) = %s [TTL: %lld, cached]\n", session->nac_address_ascii, rev->name,
			       (long long) (rev->ttl - io_now.tv_sec));
			return;
		    }
		}
	    }
	    r = r->parent;
	}
    }
#ifdef WITH_DNS
    if (session->ctx->host->lookup_revmap_nac == BISTATE_YES) {
	r = session->ctx->realm;
	while (r && !r->idc)
	    r = r->parent;
	if (r) {
	    session->revmap_pending = 1;
	    report(session, LOG_DEBUG, DEBUG_LWRES_FLAG, "Querying NAC revmap (%s)", session->nac_address_ascii);
	    io_dns_add_addr(config.default_realm->idc, &session->nac_address, (void *) set_revmap_nac, session);
	}
    }
#endif
}

#ifdef WITH_DNS
static void set_revmap_nas(struct context *ctx, char *hostname, int ttl)
{
    rb_node_t *rbn, *rbnext;

    if (!hostname)
	ttl = 60;

    report(NULL, LOG_DEBUG, DEBUG_LWRES_FLAG, "NAS revmap(%s) = %s [TTL: %d]\n", ctx->nas_address_ascii, hostname ? hostname : "(not found)", ttl);

    if (hostname)
	ctx->nas_dns_name = mempool_strdup(ctx->pool, hostname);

    ctx->revmap_pending = 0;
    ctx->revmap_timedout = 0;

    add_revmap(ctx->realm, &ctx->nas_address, hostname, ttl);

    for (rbn = RB_first(ctx->sessions); rbn; rbn = rbnext) {
	tac_session *session = RB_payload(rbn, tac_session *);
	rbnext = RB_next(rbn);

	if (!session->revmap_pending && session->resumefn)
	    resume_session(session, -1);
    }
}
#endif


void get_revmap_nas(tac_session * session)
{
    struct context *ctx = session->ctx;
    if (!ctx->nas_dns_name) {
	tac_realm *r = ctx->realm;
	while (r) {
	    int i;
	    for (i = 0; i < 3; i++) {
		if (r->dns_tree_ptr[i]) {
		    struct revmap *rev = radix_lookup(r->dns_tree_ptr[i], &ctx->nas_address, NULL);
		    if (rev && rev->name && rev->ttl >= io_now.tv_sec) {
			ctx->nas_dns_name = mempool_strdup(ctx->pool, rev->name);
			ctx->nas_dns_name_len = strlen(ctx->nas_dns_name);
			report(NULL, LOG_DEBUG, DEBUG_LWRES_FLAG, "NAS revmap(%s) = %s [TTL: %lld, cached]\n", ctx->nas_address_ascii, rev->name,
			       (long long) (rev->ttl - io_now.tv_sec));
			return;
		    }
		}
	    }
	    r = r->parent;
	}
#ifdef WITH_DNS
	if (ctx->host->lookup_revmap_nas == BISTATE_YES) {
	    r = ctx->realm;
	    while (r && !r->idc)
		r = r->parent;
	    if (r->idc) {
		ctx->revmap_pending = 1;
		report(session, LOG_DEBUG, DEBUG_LWRES_FLAG, "Querying NAS revmap (%s)", ctx->nas_address_ascii);
		io_dns_add_addr(config.default_realm->idc, &ctx->nas_address, (void *) set_revmap_nas, ctx);
	    }
	}
#endif
    }
}

#ifdef WITH_DNS
void resume_session(tac_session * session, int cur __attribute__((unused)))
{
    void (*resumefn)(tac_session *) = session->resumefn;
    report(session, LOG_DEBUG, DEBUG_LWRES_FLAG, "resuming");
    session->resumefn = NULL;
    if (session->revmap_pending)
	session->revmap_timedout = 1;
    if (session->ctx->revmap_pending)
	session->ctx->revmap_timedout = 1;
    io_sched_del(session->ctx->io, session, (void *) resume_session);
    resumefn(session);
}
#endif

void authen(tac_session * session, tac_pak_hdr * hdr)
{
    int username_required = 1;
    struct authen_start *start = tac_payload(hdr, struct authen_start *);
    struct authen_cont *cont = tac_payload(hdr, struct authen_cont *);

    report(session, LOG_DEBUG, DEBUG_AUTHEN_FLAG, "%s: hdr->seq_no: %d", __func__, hdr->seq_no);

    if (!li_user_access_verification) {
	li_user_access_verification = parse_log_format_inline("\"${USER_ACCESS_VERIFICATION}\n\n${message}${umessage}\"", __FILE__, __LINE__);
	li_username = parse_log_format_inline("\"${USERNAME}\"", __FILE__, __LINE__);
	li_password = parse_log_format_inline("\"${PASSWORD}\"", __FILE__, __LINE__);
	li_response = parse_log_format_inline("\"${RESPONSE}\"", __FILE__, __LINE__);
	li_permission_denied = parse_log_format_inline("\"${PERMISSION_DENIED}\"", __FILE__, __LINE__);
	li_enable_password = parse_log_format_inline("\"${ENABLE_PASSWORD}\"", __FILE__, __LINE__);
	li_password_old = parse_log_format_inline("\"${umessage}${PASSWORD_OLD}\"", __FILE__, __LINE__);
	li_password_abort = parse_log_format_inline("\"${PASSWORD_ABORT}\n\"", __FILE__, __LINE__);
	li_password_new = parse_log_format_inline("\"${umessage}${PASSWORD_NEW}\"", __FILE__, __LINE__);
	li_password_again = parse_log_format_inline("\"${PASSWORD_AGAIN}\"", __FILE__, __LINE__);
	li_password_nomatch = parse_log_format_inline("\"${PASSWORD_NOMATCH}\b\"", __FILE__, __LINE__);
	li_password_minreq = parse_log_format_inline("\"${PASSWORD_MINREQ}\n\"", __FILE__, __LINE__);
	li_motd_dflt = parse_log_format_inline("\"${message}${umessage}\"", __FILE__, __LINE__);
	li_password_change_dialog = parse_log_format_inline("\"${PASSWORD_CHANGE_DIALOG}\n\n\"", __FILE__, __LINE__);
	li_change_password = parse_log_format_inline("\"${CHANGE_PASSWORD}\n\"", __FILE__, __LINE__);
	li_password_incorrect = parse_log_format_inline("\"${PASSWORD_INCORRECT}\n\"", __FILE__, __LINE__);
	li_password_incorrect_retry = parse_log_format_inline("\"${PASSWORD_INCORRECT}\n${PASSWORD}\"", __FILE__, __LINE__);
	li_response_incorrect = parse_log_format_inline("\"${RESPONSE_INCORRECT}\n${RESPONSE}\"", __FILE__, __LINE__);
    }

    if (!session->authen_data)
	session->authen_data = memlist_malloc(session->memlist, sizeof(struct authen_data));

    if (hdr->seq_no == 1) {
	get_pkt_data(session, start, NULL);

	switch (start->action) {
	case TAC_PLUS_AUTHEN_LOGIN:
	    switch (start->service) {
	    case TAC_PLUS_AUTHEN_SVC_ENABLE:
		session->authen_data->authfn = do_enable;
		username_required = 0;
		break;
	    default:
		switch (start->type) {
		case TAC_PLUS_AUTHEN_TYPE_ASCII:
		    if (((session->ctx->bug_compatibility & CLIENT_BUG_INVALID_START_DATA) || (common_data.debug & DEBUG_TACTRACE_FLAG)) && start->user_len
			&& start->data_len) {
			/* PAP-like inbound login. Not in rfc8907, but used by IOS-XR. */
			session->authen_data->authfn = do_login;
		    } else {
			/* Standard ASCII login */
			session->authen_data->authfn = do_ascii_login;
			session->passwd_changeable = 1;
			username_required = 0;
			start->data_len = 0;	/* rfc8907 5.4.2.1 says to ignore the data field */
		    }
		    break;
		case TAC_PLUS_AUTHEN_TYPE_PAP:
		    session->authen_data->authfn = do_pap;
		    break;
		case TAC_PLUS_AUTHEN_TYPE_CHAP:
		    if (hdr->version == TAC_PLUS_VER_ONE)
			session->authen_data->authfn = do_chap;
		    break;
#ifdef WITH_CRYPTO
		case TAC_PLUS_AUTHEN_TYPE_MSCHAP:
		    if (hdr->version == TAC_PLUS_VER_ONE)
			session->authen_data->authfn = do_mschap;
		    break;
		case TAC_PLUS_AUTHEN_TYPE_MSCHAPV2:
		    if (hdr->version == TAC_PLUS_VER_ONE)
			session->authen_data->authfn = do_mschapv2;
		    break;
#endif
		case TAC_PLUS_AUTHEN_TYPE_SSHKEY:
		    // limit to hdr->version? 1.2 perhaps?
		    session->authen_data->authfn = do_sshkeyhash;
		    break;
		case TAC_PLUS_AUTHEN_TYPE_SSHCERT:
		    // limit to hdr->version? 1.2 perhaps?
		    session->authen_data->authfn = do_sshcerthash;
		    break;
#ifdef WITH_CRYPTO
		case TAC_PLUS_AUTHEN_TYPE_EAP:
		    // limit to hdr->version? 1.2 perhaps?
		    session->authen_data->authfn = do_eap;
		    break;
#endif
		}
	    }
	    break;
	case TAC_PLUS_AUTHEN_CHPASS:
	    if (session->ctx->realm->chpass == TRISTATE_YES)
		switch (start->type) {
		case TAC_PLUS_AUTHEN_TYPE_ASCII:
		    session->authen_data->authfn = do_chpass;
		    session->chpass = 1;
		    session->passwd_changeable = 1;
		    username_required = 0;
		    break;
		}
	    break;
	}

	if (session->authen_data->authfn) {
	    u_char *p = (u_char *) start + TAC_AUTHEN_START_FIXED_FIELDS_SIZE;
	    session->username = memlist_strndup(session->memlist, p, start->user_len);
	    session->username_len = start->user_len;

	    p += start->user_len;
	    session->nas_port = memlist_strndup(session->memlist, p, start->port_len);
	    session->nas_port_len = start->port_len;
	    p += start->port_len;
	    session->nac_address_ascii = memlist_strndup(session->memlist, p, start->rem_addr_len);
	    session->nac_address_ascii_len = start->rem_addr_len;
	    session->nac_address_valid = v6_ptoh(&session->nac_address, NULL, session->nac_address_ascii) ? 0 : 1;
	    if (session->nac_address_valid)
		get_revmap_nac(session);
	    p += start->rem_addr_len;
	    session->authen_data->data = (u_char *) memlist_strndup(session->memlist, p, start->data_len);
	    session->authen_data->data_len = start->data_len;

	    session->priv_lvl = start->priv_lvl;
	    if (session->priv_lvl & ~0xf) {
		send_authen_error(session, "Invalid privilege level %d in packet.", session->priv_lvl);
		return;
	    }
	    session->privlvl_len = snprintf(session->privlvl, sizeof(session->privlvl), "%u", session->priv_lvl);
	}
    } else if (cont->flags & TAC_PLUS_CONTINUE_FLAG_ABORT) {
	char *t = hints[hint_abort].plain;
	size_t l = ntohs(cont->user_data_len) + 100;
	char *tmp = alloca(l);
	if (cont->user_data_len) {
	    snprintf(tmp, l, "%s (%*s)", t, cont->user_msg_len, (char *) cont + TAC_AUTHEN_CONT_FIXED_FIELDS_SIZE + ntohs(cont->user_msg_len));
	    t = tmp;
	}
	report_auth(session, t, hint_abort, TAC_PLUS_AUTHEN_STATUS_FAIL);
	cleanup_session(session);
	return;
    } else {			/* hdr->seq_no != 1 */
	username_required = 0;
	// memlist_free(session->mempool, &session->authen_data);
	// memlist_free(session->mempool, &session->authen_msg);
	// session->authen_data->msg = NULL;
	// session->authen_data->data = NULL;
	session->authen_data->msg = memlist_strndup(session->memlist, (u_char *) cont + TAC_AUTHEN_CONT_FIXED_FIELDS_SIZE, ntohs(cont->user_msg_len));
	session->authen_data->msg_len = ntohs(cont->user_msg_len);
	session->authen_data->data = (u_char *)
	    memlist_strndup(session->memlist, (u_char *) cont + TAC_AUTHEN_CONT_FIXED_FIELDS_SIZE + ntohs(cont->user_msg_len), ntohs(cont->user_data_len));
	session->authen_data->data_len = ntohs(cont->user_data_len);
    }

    if (session->authen_data->authfn) {
	if (username_required && !session->username[0])
	    send_authen_error(session, "No username in packet");
	else {
#ifdef WITH_DNS
	    if ((hdr->seq_no == 1) && (session->ctx->host->dns_timeout > 0) && (session->revmap_pending || session->ctx->revmap_pending)) {
		session->resumefn = session->authen_data->authfn;
		io_sched_add(session->ctx->io, session, (void *) resume_session, session->ctx->host->dns_timeout, 0);
	    } else
#endif
		session->authen_data->authfn(session);
	}
    } else
	send_authen_error(session, "Invalid or unsupported AUTHEN/START (action=%d authen_type=%d)", start->action, start->type);
}

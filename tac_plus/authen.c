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

struct hint_struct {
    char *plain;
    char *msgid;
};

struct hint_struct hints[hint_max] = {
    { " failed", "AUTHCFAIL" },
    { " failed (denied)", "AUTHCFAIL-DENY" },
    { " failed (password not set)", "AUTHCFAIL-NOPASS" },
    { " failed (expired)", "AUTHCFAIL-EXPIRE" },
    { " failed (no such user)", "AUTHC-FAILNOUSER" },
    { " rejected", "AUTHC-FAILREJECT" },
    { " delegated", "AUTHCDELEGATE" },
    { " succeeded", "AUTHCSUCCESS" },
    { " succeeded (permitted)", "AUTHCSUCCESS-PERMIT" },
    { " failed (no clear text password set)", "AUTHCFAIL-NOTEXTPASS" },
    { " failed (backend error)", "AUTHCFAIL-BACKEND" },
    { " denied by user profile", "AUTHCFAIL-USERPROFILE" },
    { " failed (retry with identical password)", "AUTHCFAIL-DENY-RETRY" },
    { " failed (This might be a bug, consider reporting it!)", "AUTHCFAIL-BUG" },
    { " aborted by request", "AUTHCFAIL-ABORT" },
    { " denied by ACL", "AUTHCFAIL-ACL" },
    { " denied (NAS address not permitted)", "AUTHCFAIL-NAS" },
    { " denied (NAC address not permitted)", "AUTHCFAIL-NAC" },
    { " denied (invalid challenge length)", "AUTHCFAIL-BAD-CHALLENGE-LENGTH" },
    { " denied (minimum password requirements not met)", "AUTHCFAIL-WEAKPASSWORD" },
};

static char *get_hint(tac_session * session, enum hint_enum h)
{
    if (session->user_msg) {
	size_t n = strlen(hints[h].plain) + strlen(session->user_msg) + 20;
	char *t, *hint;
	hint = mem_alloc(session->mem, n);
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

static void report_auth(tac_session * session, char *what, enum hint_enum hint)
{
    char *aaarealm = alloca(strlen(session->ctx->aaa_realm->name) + 40);
    char *nacrealm = alloca(strlen(session->ctx->nac_realm->name) + 40);
    char *hint_augmented;

    rb_tree_t *rbt = session->ctx->aaa_realm->access;

    if (session->ctx->aaa_realm == config.top_realm)
	*aaarealm = 0;
    else {
	strcpy(aaarealm, " (realm: ");
	strcat(aaarealm, session->ctx->aaa_realm->name);
	strcat(aaarealm, ")");
    }

    if ((session->ctx->nac_realm == config.top_realm) || !session->username[0])
	*nacrealm = 0;
    else {
	strcpy(nacrealm, " (realm: ");
	strcat(nacrealm, session->ctx->nac_realm->name);
	strcat(nacrealm, ")");
    }

    hint_augmented = get_hint(session, hint);

    report(session, LOG_INFO, ~0,
	   "%s%s%s%s%s%s%s%s%s%s%s",
	   what,
	   session->username[0] ? " for '" : "", session->username,
	   session->username[0] ? "'" : "", aaarealm,
	   session->nac_address_ascii[0] ? " from " : "",
	   session->nac_address_ascii, nacrealm, session->nas_port[0] ? " on " : "", session->nas_port, hint_augmented);

    if (rbt) {
	log_start(rbt, session->ctx->nas_address_ascii, hints[hint].msgid);
	log_write(rbt, session->username, strlen(session->username));
	log_write_separator(rbt);
	if (session->nas_port)
	    log_write(rbt, session->nas_port, strlen(session->nas_port));
	log_write_separator(rbt);
	if (session->nac_address_ascii)
	    log_write(rbt, session->nac_address_ascii, strlen(session->nac_address_ascii));
	log_write_separator(rbt);
	log_write(rbt, what, strlen(what));
	log_write(rbt, hint_augmented, strlen(hint_augmented));
	log_flush(rbt);
    }
}

static int password_requirements_failed(tac_session * session, char *what)
{
    tac_realm *r = session->ctx->aaa_realm;

    if (r->password_acl) {
	enum token token;
	u_int debug = session->debug;
	if (!(session->debug & DEBUG_USERINPUT_FLAG))
	    session->debug = 0;
	token = eval_tac_acl(session, NULL, r->password_acl);
	session->debug = debug;
	switch (token) {
	case S_permit:
	    if (r->password_acl_negate)
		token = S_deny;
	    break;
	default:
	    if (r->password_acl_negate)
		token = S_permit;
	}
	if (token != S_permit) {
	    report(session, LOG_ERR, ~0, "password doesn't meet minimum requirements");
	    report_auth(session, what, hint_weak_password);
	    send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_FAIL, "Password doesn't meet minimum requirements.\n", 0, NULL, 0, 0);
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

static int compare_pwdat(struct pwdat *a, char *b, enum hint_enum *hint, char **follow __attribute__((unused)))
{
    int res = -1;

    switch (a->type) {
    case S_clear:
	res = strcmp(a->value, b);
	break;
    case S_crypt:
	if (a->value[0] == '$' && a->value[1] == '1' && a->value[2] == '$')
	    res = strcmp(a->value, md5crypt(b, a->value));
	else
	    res = strcmp(a->value, crypt(b, a->value));
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
#ifdef SUPPORT_FOLLOW
    case S_follow:
	*follow = a->value;
	*hint = hint_delegated;
	return TAC_PLUS_AUTHEN_STATUS_FOLLOW;
#endif
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

static tac_user *lookup_and_set_user(tac_session * session)
{
    tac_rewrite_user(session);
    report(session, LOG_DEBUG, DEBUG_AUTHEN_FLAG, "looking for user %s realm %s", session->username, session->ctx->aaa_realm->name);
    if (!session->user_is_session_specific)
	session->user = lookup_user(session->ctx->aaa_realm->usertable, session->username);
    if (session->user && session->user->fallback_only && ((session->ctx->authfallback != TRISTATE_YES)
							  || !session->ctx->aaa_realm->last_backend_failure
							  || (session->ctx->aaa_realm->last_backend_failure +
							      session->ctx->aaa_realm->backend_failure_period < io_now.tv_sec))) {
	report(session, LOG_DEBUG, DEBUG_AUTHEN_FLAG, "Not in emergency mode, ignoring user %s", session->user->name);
	if (session->user_is_session_specific)
	    free_user(session->user);
	session->user = NULL;
    }

    if (session->user) {
	cfg_get_debug(session, &session->debug);
	session->passwdp = eval_passwd_acl(session);
    }
    report(session, LOG_DEBUG, DEBUG_AUTHEN_FLAG, "user lookup %s", session->user ? "succeded" : "failed");
    return session->user;
}

static int query_mavis_auth_login(tac_session * session, void (*f)(tac_session *), enum pw_ix pw_ix)
{
    int res = !session->flag_mavis_auth &&( (session->ctx->aaa_realm->mavis_userdb && !session->ctx->aaa_realm->mavis_login_prefetch && !session->user)
					   ||(session->user && pw_ix == PW_MAVIS));
    session->flag_mavis_auth = 1;
    if (res)
	mavis_lookup(session, f, AV_V_TACTYPE_AUTH, PW_LOGIN);
    return res;
}

static int query_mavis_info_login(tac_session * session, void (*f)(tac_session *))
{
    int res = !session->flag_mavis_info && !session->user && session->ctx->aaa_realm->mavis_login_prefetch;
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
	( (session->ctx->aaa_realm->mavis_userdb && !session->ctx->aaa_realm->mavis_pap_prefetch && !session->user) ||(session->user && pw_ix == PW_MAVIS));
    session->flag_mavis_auth = 1;
    if (res)
	mavis_lookup(session, f, AV_V_TACTYPE_AUTH, PW_PAP);
    return res;
}

static int query_mavis_info_pap(tac_session * session, void (*f)(tac_session *))
{
    int res = !session->user && session->ctx->aaa_realm->mavis_pap_prefetch && !session->flag_mavis_info;
    session->flag_mavis_info = 1;
    if (res)
	mavis_lookup(session, f, AV_V_TACTYPE_INFO, PW_PAP);
    return res;
}

void set_taglist(tac_session * session)
{
    if (session->user)
	session->tag = eval_taglist(session, session->user);
}

#ifdef WITH_CRYPTO
#ifdef SUPPORT_ARAP
static void do_arap(tac_session * session)
{
    int res = TAC_PLUS_AUTHEN_STATUS_FAIL, data_len = 0;
    u_char *data = NULL, r_chal[8];
    enum hint_enum hint = hint_default;

    lookup_and_set_user(session);
    if (query_mavis_info(session, do_arap, PW_ARAP))
	return;

    if (session->user) {
	set_taglist(session);

	if (session->passwdp->passwd[PW_ARAP]->type != S_clear) {
	    hint = hint_no_cleartext;
	    res = TAC_PLUS_AUTHEN_STATUS_FAIL;
	} else if (session->authen_data->data_len == 24) {
	    struct DES_ks ks;
	    char cypher[8];
	    char nas_chal[8], r_resp[8], secret[8];
	    u_int i;
	    memcpy(nas_chal, session->authen_data->data, (size_t) 8);
	    memcpy(r_chal, session->authen_data->data + 8, (size_t) 8);
	    memcpy(r_resp, session->authen_data->data + 16, (size_t) 8);
	    memset(secret, 0, sizeof(secret));
	    strncpy(secret, session->passwdp->passwd[PW_ARAP]->value, sizeof(secret));
	    /* Set the parity bit to zero */
	    for (i = 0; i < sizeof(secret); i++)
		secret[i] <<= 1;
	    memset(&ks, 0, sizeof(ks));
	    DES_set_key((DES_cblock *) secret, &ks);
	    DES_ecb_encrypt((DES_cblock *) nas_chal, (DES_cblock *) cypher, &ks, DES_ENCRYPT);
	    memcpy(nas_chal, cypher, sizeof(nas_chal));
	    /* Compare the remote's response value with the just
	     * calculated value. If they are equal, it's a pass,
	     * otherwise it's a failure
	     */
	    if (memcmp(nas_chal, r_resp, (size_t) 8)) {
		res = TAC_PLUS_AUTHEN_STATUS_FAIL;
		hint = hint_failed;
	    } else {
		res = TAC_PLUS_AUTHEN_STATUS_PASS;
		hint = hint_succeeded;
	    }

	    if (res == TAC_PLUS_AUTHEN_STATUS_PASS)
		res = user_invalid(session->user, &hint);

	    if (res == TAC_PLUS_AUTHEN_STATUS_PASS)
		res = cfg_get_access_nas(session, &hint);

	    if (res == TAC_PLUS_AUTHEN_STATUS_PASS)
		res = cfg_get_access_acl(session, &hint);

	    if (res == TAC_PLUS_AUTHEN_STATUS_PASS) {
		/* Calculate the response to the remote's challenge */
		memset(&ks, 0, sizeof(ks));
		DES_set_key((DES_cblock *) secret, &ks);
		DES_ecb_encrypt((DES_cblock *) r_chal, (DES_cblock *) cypher, &ks, DES_ENCRYPT);
		memcpy(r_chal, cypher, sizeof(r_chal));
		data_len = 8;
		data = r_chal;
	    }
	}
    }

    report_auth(session, "arap login", hint);

    send_authen_reply(session, res, NULL, 0, data, data_len, 0);
}
#endif
#endif

static void do_chap(tac_session * session)
{
    int res = TAC_PLUS_AUTHEN_STATUS_FAIL;
    enum hint_enum hint = hint_default;

    lookup_and_set_user(session);
    if (query_mavis_info(session, do_chap, PW_CHAP))
	return;

    if (session->user) {
	set_taglist(session);
	res = user_invalid(session->user, &hint);
	if (res == TAC_PLUS_AUTHEN_STATUS_PASS) {
	    if (session->passwdp->passwd[PW_CHAP]->type != S_clear) {
		hint = hint_no_cleartext;
		res = TAC_PLUS_AUTHEN_STATUS_FAIL;
	    } else if (session->authen_data->data_len - MD5_LEN > 0) {
		u_char digest[MD5_LEN];
		myMD5_CTX mdcontext;

		myMD5Init(&mdcontext);
		myMD5Update(&mdcontext, session->authen_data->data, (size_t) 1);
		myMD5Update(&mdcontext, (u_char *) session->passwdp->passwd[PW_CHAP]->value, strlen(session->passwdp->passwd[PW_CHAP]->value));
		myMD5Update(&mdcontext, session->authen_data->data + 1, (size_t) (session->authen_data->data_len - 1 - MD5_LEN));
		myMD5Final(digest, &mdcontext);

		if (memcmp(digest, session->authen_data->data + session->authen_data->data_len - MD5_LEN, (size_t) MD5_LEN)) {
		    res = TAC_PLUS_AUTHEN_STATUS_FAIL;
		    hint = hint_failed;
		} else {
		    res = TAC_PLUS_AUTHEN_STATUS_PASS;
		    hint = hint_succeeded;

		    if (res == TAC_PLUS_AUTHEN_STATUS_PASS)
			res = cfg_get_access_nas(session, &hint);
		    if (res == TAC_PLUS_AUTHEN_STATUS_PASS)
			res = cfg_get_access_acl(session, &hint);
		}
	    }
	}
    }

    report_auth(session, "chap login", hint);

    send_authen_reply(session, res, NULL, 0, NULL, 0, 0);
}

#ifdef SUPPORT_SENDAUTH
static void do_chap_out(tac_session * session)
{
    int res = TAC_PLUS_AUTHEN_STATUS_FAIL, data_len = 0;
    u_char digest[MD5_LEN], *data = NULL;
    enum hint_enum hint = hint_default;

    lookup_and_set_user(session);
    if (query_mavis_info(session, do_chap_out, PW_CHAP))
	return;

    if (session->user) {
	set_taglist(session);

	if (session->passwdp->passwd[PW_CHAP]->type != S_clear)
	    hint = hint_no_cleartext;
	else if (session->authen_data->data_len > 0) {
	    res = user_invalid(session->user, &hint);
	    if (res == TAC_PLUS_AUTHEN_STATUS_PASS) {
		myMD5_CTX mdcontext;

		MD5Init(&mdcontext);
		MD5Update(&mdcontext, session->authen_data->data, (size_t) 1);
		MD5Update(&mdcontext, (u_char *) session->passwdp->passwd[PW_CHAP]->value, strlen(session->passwdp->passwd[PW_CHAP]->value));
		MD5Update(&mdcontext, session->authen_data->data + 1, (size_t) (session->authen_data->data_len - 1));
		MD5Final(digest, &mdcontext);
	    }

	    if (res == TAC_PLUS_AUTHEN_STATUS_PASS)
		res = cfg_get_access_nas(session, &hint);
	    if (res == TAC_PLUS_AUTHEN_STATUS_PASS)
		res = cfg_get_access_acl(session, &hint);
	    if (res == TAC_PLUS_AUTHEN_STATUS_PASS)
		data = digest, data_len = MD5_LEN;
	}
    }

    report_auth(session, "outbound chap request", hint);

    send_authen_reply(session, res, NULL, 0, data, data_len, 0);
}
#endif

static char *subst_magic(tac_session * session, char *format, ...)
{
    va_list ap;
    char *f = format, *format_concat, *u, *t, *format_intermediate = NULL, *res = NULL;
    time_t dummy = (time_t) io_now.tv_sec;
    size_t len = 0, i;

    va_start(ap, format);
    for (f = format; f; f = (char *) va_arg(ap, char *))
	 len += *f ? strlen(f) + 1 : 0;
    va_end(ap);

    if (!len)
	return NULL;

    format_concat = alloca(len);
    *format_concat = 0;

    va_start(ap, format);
    for (f = format; f; f = (char *) va_arg(ap, char *)) {
	if ((f != format) && *f)
	    strcat(format_concat, "\n");
	strcat(format_concat, f);
    }
    va_end(ap);

    len += 512;			// should be sufficient for strftime(3) substitutions
    format_intermediate = alloca(len + 1);
    i = strftime(format_intermediate, len, format_concat, localtime(&dummy));

    if (!i)
	return NULL;

    /* connection dependent substitutions */
    for (u = format_intermediate; *u; u++)
	if (*u == '%')
	    switch (*(++u)) {
	    case '\0':
		i++, u--;
		continue;
	    case 'R':		/* router name */
		if (session->ctx->nas_dns_name && *session->ctx->nas_dns_name) {
		    i += strlen(session->ctx->nas_dns_name);
		    break;
		}
		/* fallthrough */
	    case 'r':		/* router ip */
		i += strlen(session->ctx->nas_address_ascii);
		break;
	    case 'C':		/* client name */
		if (session->nac_dns_name && *session->nac_dns_name) {
		    i += strlen(session->nac_dns_name);
		    break;
		}
		/* fallthrough */
	    case 'c':		/* client address */
		i += strlen(session->nac_address_ascii);
		break;
	    case 'p':		/* router port */
		i += strlen(session->nas_port);
		break;
	    case 'u':		/* username */
		i += strlen(session->username);
		break;
	    case '%':		/* literal % */
		i++;
		break;
	} else
	    i++;

    t = res = mem_alloc(session->mem, ++i);

    for (u = format_intermediate; *u; u++)
	if (*u == '%') {
	    switch (*(++u)) {
	    case '\0':
		u--;
		continue;
	    case 'R':		/* router name */
		if (session->ctx->nas_dns_name && *session->ctx->nas_dns_name) {
		    strcpy(t, session->ctx->nas_dns_name);
		    break;
		}
	    case 'r':		/* router ip */
		strcpy(t, session->ctx->nas_address_ascii);
		break;
	    case 'C':		/* client name */
		if (session->nac_dns_name && *session->nac_dns_name) {
		    strcpy(t, session->nac_dns_name);
		    break;
		}
	    case 'c':		/* client address */
		strcpy(t, session->nac_address_ascii);
		break;
	    case 'p':		/* router port */
		strcpy(t, session->nas_port);
		break;
	    case 'u':		/* username */
		strcpy(t, session->username);
		break;
	    case '%':		/* literal % */
		strcpy(t, "%");
		break;
	    }
	    while (*t)
		t++;
	} else
	    *t++ = *u;
    *t = 0;

    return res;
}

static int check_access(tac_session * session, struct pwdat *pwdat, char *passwd, enum hint_enum *hint, char **resp, char **follow)
{
    int res = TAC_PLUS_AUTHEN_STATUS_FAIL;

    if (session->mavisauth_res) {
	res = session->mavisauth_res;
	session->mavisauth_res = 0;
	if (res == TAC_PLUS_AUTHEN_STATUS_ERROR && session->ctx->authfallback != TRISTATE_YES)
	    res = TAC_PLUS_AUTHEN_STATUS_FAIL;
    } else if (pwdat)
	res = compare_pwdat(pwdat, passwd, hint, follow);

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

    if (session->user) {
	mem_free(session->mem, &session->password_bad);
	if (res == TAC_PLUS_AUTHEN_STATUS_PASS) {
	    mem_free(session->mem, &session->password);
	    res = cfg_get_access(session, hint);
	    if (res != TAC_PLUS_AUTHEN_STATUS_PASS && session->ctx->reject_banner)
		*resp = subst_magic(session, session->ctx->reject_banner, NULL);
	    if (res == TAC_PLUS_AUTHEN_STATUS_PASS)
		res = user_invalid(session->user, hint);
	} else {
	    session->password_bad = session->password;
	    session->password = NULL;
	}
    }

    return res;
}

static void set_pwdat(tac_session * session, struct pwdat **pwdat, enum pw_ix *pw_ix)
{
    if (session->user) {
	*pwdat = session->passwdp->passwd[*pw_ix];
	if ((*pwdat)->type == S_login) {
	    *pw_ix = PW_LOGIN;
	    *pwdat = session->passwdp->passwd[*pw_ix];
	}
	if ((*pwdat)->type == S_mavis) {
	    *pw_ix = PW_MAVIS;
	    *pwdat = session->passwdp->passwd[*pw_ix];
	}
    } else
	*pwdat = NULL;
}


static char *set_welcome_banner(tac_session * session, char *fmt_dflt, char *msg)
{
    char *fmt;

    if (session->welcome_banner)
	return msg;

    fmt = ((session->ctx->authfallback != TRISTATE_YES)
	   || !session->ctx->welcome_banner_fallback
	   || !session->ctx->aaa_realm->last_backend_failure
	   || (session->ctx->aaa_realm->last_backend_failure +
	       session->ctx->aaa_realm->backend_failure_period < io_now.tv_sec)) ? session->ctx->welcome_banner : session->ctx->welcome_banner_fallback;

    if (!fmt)
	fmt = fmt_dflt;

    if (!fmt)
	fmt = "";

    return (session->welcome_banner = subst_magic(session, fmt, msg, NULL));
}

static char *set_motd_banner(tac_session * session, char *msg)
{
    char *umsg = NULL;
    char *motd = session->ctx->motd;

    if (session->motd || (cfg_get_hushlogin(session) == TRISTATE_YES))
	return NULL;

    cfg_get_message(session, &umsg);

    if (!msg && !umsg && !motd)
	return NULL;

    if (!motd)
	motd = "";
    if (!umsg)
	umsg = "";

    return (session->motd = subst_magic(session, motd, umsg, msg, NULL));
}

static void do_chpass(tac_session * session)
{
    enum pw_ix pw_ix = PW_LOGIN;
    int res = TAC_PLUS_AUTHEN_STATUS_FAIL;
    enum hint_enum hint = hint_default;
    char *follow = NULL, *resp = NULL;
    struct pwdat *pwdat = NULL;

    if (!session->username[0] && session->authen_data->msg) {
	mem_free(session->mem, &session->username);
	session->username = session->authen_data->msg;
	session->tag = strchr(session->username, session->ctx->aaa_realm->separator);
	if (session->tag)
	    *session->tag++ = 0;
	session->authen_data->msg = NULL;
    }
    if (!session->username[0]) {
	send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_GETUSER, set_welcome_banner(session, "\nUser Access Verification\n", "Username: "), 0, NULL, 0, 0);
	return;
    }

    if (!session->password && session->authen_data->msg) {
	session->password = session->authen_data->msg;
	session->authen_data->msg = NULL;
	if (password_requirements_failed(session, "password change"))
	    return;
    }
    if (!session->password) {
	send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_GETDATA, "Old password: ", 0, NULL, 0, TAC_PLUS_REPLY_FLAG_NOECHO);
	return;
    }
    if (!session->password[0]) {
	send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_FAIL, "Password change dialog aborted.\n", 0, NULL, 0, 0);
	return;
    }
    if (!session->password_new && session->authen_data->msg) {
	session->password_new = session->authen_data->msg;
	session->authen_data->msg = NULL;
	if (password_requirements_failed(session, "password change"))
	    return;
    }
    if (!session->password_new) {
	send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_GETPASS, "New password: ", 0, NULL, 0, TAC_PLUS_REPLY_FLAG_NOECHO);
	return;
    }
    if (!session->password_new[0]) {
	send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_FAIL, "Password change dialog aborted.\n", 0, NULL, 0, 0);
	return;
    }
    if (!session->authen_data->msg) {
	send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_GETPASS, "Retype new password: ", 0, NULL, 0, TAC_PLUS_REPLY_FLAG_NOECHO);
	return;
    }

    if (strcmp(session->authen_data->msg, session->password_new)) {
	send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_FAIL, "Passwords do not match.\n", 0, NULL, 0, 0);
	return;
    }

    lookup_and_set_user(session);
    if (query_mavis_info_login(session, do_chpass))
	return;

    set_pwdat(session, &pwdat, &pw_ix);
    set_taglist(session);

    if (!session->flag_mavis_auth && ((!session->ctx->aaa_realm->mavis_login_prefetch && !session->user) || (session->user && pw_ix == PW_MAVIS))) {
	session->flag_mavis_auth = 1;
	mavis_lookup(session, do_chpass, AV_V_TACTYPE_CHPW, PW_LOGIN);
	return;
    }

    res = check_access(session, pwdat, session->password_new, &hint, &resp, &follow);

    if (res == TAC_PLUS_AUTHEN_STATUS_PASS)
	session->passwd_mustchange = 0;

    report_auth(session, "password change", hint);

    send_authen_reply(session, res, resp ? resp : set_motd_banner(session, NULL), 0, (u_char *) follow, 0, 0);
}

static void send_password_prompt(tac_session * session, enum pw_ix pw_ix, void (*f)(tac_session *))
{
    char *banner;

    if (session->ctx->aaa_realm->chalresp && (!session->user || ((pw_ix == PW_MAVIS) && (TRISTATE_NO != session->user->chalresp)))) {
	if (!session->flag_chalresp) {
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
	    strcat(chal, "\nResponse: ");
	    if (session->welcome_banner)
		banner = chal;
	    else
		banner = set_welcome_banner(session, "", chal);
	    send_authen_reply(session,
			      TAC_PLUS_AUTHEN_STATUS_GETPASS, banner, 0, NULL, 0, session->ctx->aaa_realm->chalresp_noecho ? TAC_PLUS_REPLY_FLAG_NOECHO : 0);
	    return;
	}
    }

    if (session->welcome_banner)
	banner = "Password: ";
    else
	banner = set_welcome_banner(session, "", "Password: ");

    send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_GETPASS, banner, 0, NULL, 0, TAC_PLUS_REPLY_FLAG_NOECHO);
}

/* enable with login password */
static void do_enable_login(tac_session * session)
{
    enum pw_ix pw_ix = PW_LOGIN;
    struct pwdat *pwdat = NULL;
    enum hint_enum hint = hint_default;
    char *follow = NULL, *resp = "Permission denied.";
    int res = TAC_PLUS_AUTHEN_STATUS_FAIL;
    char buf[40];

    lookup_and_set_user(session);
    if (query_mavis_info_login(session, do_enable_login))
	return;

    snprintf(buf, sizeof(buf), "enable %d", session->priv_lvl);

    set_pwdat(session, &pwdat, &pw_ix);

    if (!pwdat || pwdat->type != S_follow) {

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
    }

    pw_ix = PW_LOGIN;
    set_pwdat(session, &pwdat, &pw_ix);

    if (query_mavis_auth_login(session, do_enable_login, pw_ix))
	return;

    res = check_access(session, pwdat, session->password, &hint, &resp, NULL);

    mem_free(session->mem, &session->challenge);

    report_auth(session, buf, hint);

    send_authen_reply(session, res, res == TAC_PLUS_AUTHEN_STATUS_PASS ? NULL : resp, 0, (u_char *) follow, 0, 0);
}

static void do_enable_getuser(tac_session *);

static void do_enable_augmented(tac_session * session)
{
    enum pw_ix pw_ix = PW_LOGIN;
    struct pwdat *pwdat = NULL;
    int res = TAC_PLUS_AUTHEN_STATUS_FAIL;
    enum hint_enum hint = hint_default;
    char *follow = NULL, *resp = "Permission denied.", *u;

    lookup_and_set_user(session);

    if (query_mavis_info_login(session, do_enable_augmented))
	return;

    if ((!session->enable || (session->enable->type != S_permit && session->enable->type != S_follow)) && !session->authen_data->msg) {
	send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_GETPASS, "Password: ", 0, NULL, 0, TAC_PLUS_REPLY_FLAG_NOECHO);
	return;
    }

    if (session->authen_data->msg) {
	u = strchr(session->authen_data->msg, ' ');
	if (u) {
	    *u++ = 0;
	    session->username = session->authen_data->msg;
	    session->password = u;
	    session->authen_data->msg = NULL;
	    if (password_requirements_failed(session, "enable login"))
		return;
	    lookup_and_set_user(session);
	}
    }

    set_pwdat(session, &pwdat, &pw_ix);
    set_taglist(session);

    if (session->username[0]) {
	if (query_mavis_auth_login(session, do_enable_augmented, pw_ix))
	    return;

	cfg_get_enable(session, &session->enable);

	if (session->enable) {
	    if (session->enable->type == S_login)
		res = check_access(session, pwdat, session->password, &hint, &resp, &follow);
	    else
		hint = hint_denied_profile;
	}
    }

    report_auth(session, "enable login", hint);

    send_authen_reply(session, res, ((res == TAC_PLUS_AUTHEN_STATUS_PASS) ? NULL : resp), 0, (u_char *) follow, 0, 0);
}

static void do_enable(tac_session * session)
{
    int res = TAC_PLUS_AUTHEN_STATUS_FAIL;
    enum hint_enum hint = hint_default;
    char *follow = NULL;
    char buf[40];

    if ((session->ctx->augmented_enable == TRISTATE_YES) && (S_permit == eval_tac_acl(session, NULL, session->ctx->aaa_realm->enable_user_acl))
	) {
	session->username[0] = 0;
	session->authen_data->authfn = do_enable_augmented;
	do_enable_augmented(session);
	return;
    }

    if ((!session->username[0] || (S_permit == eval_tac_acl(session, NULL, session->ctx->aaa_realm->enable_user_acl)))
	&& !session->enable_getuser && (session->ctx->anon_enable == TRISTATE_NO)) {
	session->enable_getuser = 1;
	session->username[0] = 0;
	session->authen_data->authfn = do_enable_getuser;
	do_enable_getuser(session);
	return;
    }

    lookup_and_set_user(session);
    if (query_mavis_info(session, do_enable, PW_LOGIN))
	return;

    set_taglist(session);

    if (!session->enable) {
	cfg_get_enable(session, &session->enable);
	if (!session->enable)
	    session->enable = session->ctx->enable[session->priv_lvl];
    }

    if (session->enable && session->enable_getuser && (session->enable->type == S_permit))
	res = TAC_PLUS_AUTHEN_STATUS_PASS;
    else {
	if (session->user && session->enable && (session->enable->type == S_login)) {
	    session->authen_data->authfn = do_enable_login;
	    session->flag_mavis_auth = 0;
	    do_enable_login(session);
	    return;
	}
	if ((!session->enable || (session->enable->type != S_permit && session->enable->type != S_follow)) && !session->authen_data->msg) {
	    send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_GETPASS,
			      session->enable_getuser ? "Enable Password: " : "Password: ", 0, NULL, 0, TAC_PLUS_REPLY_FLAG_NOECHO);
	    return;
	}

	if (session->enable)
	    res = compare_pwdat(session->enable, session->authen_data->msg, &hint, &follow);
    }

    snprintf(buf, sizeof(buf), "enable %d", session->priv_lvl);

    report_auth(session, buf, hint);

    send_authen_reply(session, res, ((res == TAC_PLUS_AUTHEN_STATUS_PASS) ? NULL : "Permission denied."), 0, (u_char *) follow, 0, 0);
}

static void do_ascii_login(tac_session * session)
{
    enum pw_ix pw_ix = PW_LOGIN;
    struct pwdat *pwdat = NULL;
    enum hint_enum hint = hint_default;
    char *follow = NULL, *resp = NULL;
    int res = TAC_PLUS_AUTHEN_STATUS_FAIL;

    if (session->username_default && !session->username[0]) {
	mem_free(session->mem, &session->username);
	session->username = mem_strdup(session->mem, session->username_default);
    }

    if (!session->username[0] && session->authen_data->msg) {
	mem_free(session->mem, &session->username);
	session->username = session->authen_data->msg;
	session->authen_data->msg = NULL;
	session->tag = strchr(session->username, session->ctx->aaa_realm->separator);
	if (session->tag)
	    *session->tag++ = 0;
    }

    if (!session->username[0]) {
	send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_GETUSER, set_welcome_banner(session, "\nUser Access Verification\n", "Username: "), 0, NULL, 0, 0);
	return;
    }

    lookup_and_set_user(session);
    if (query_mavis_info_login(session, do_ascii_login))
	return;
    set_pwdat(session, &pwdat, &pw_ix);

    if (!pwdat || (pwdat->type != S_follow && pwdat->type != S_permit)) {
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

	if (session->ctx->aaa_realm->chpass && (!session->user || ((session->user->chalresp != TRISTATE_YES) && !session->user->passwd_oneshot))
	    && (!session->password[0] && (pw_ix == PW_MAVIS || session->ctx->aaa_realm->mavis_userdb))) {
	    mem_free(session->mem, &session->password);
	    session->authen_data->authfn = do_chpass;
	    send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_GETDATA,
			      "Entering password change dialog\n\n" "Old password: ", 0, NULL, 0, TAC_PLUS_REPLY_FLAG_NOECHO);
	    return;
	}
    }

    pw_ix = PW_LOGIN;
    set_pwdat(session, &pwdat, &pw_ix);
    set_taglist(session);

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
	res = check_access(session, pwdat, session->password, &hint, &resp, &follow);
	session->password_bad_again = 0;
    }

    mem_free(session->mem, &session->challenge);

    report_auth(session, "shell login", hint);

    switch (res) {
#ifdef SUPPORT_FOLLOW
    case TAC_PLUS_AUTHEN_STATUS_FOLLOW:
	send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_FOLLOW, NULL, 0, (u_char *) follow, 0, 0);
	return;
#endif
    case TAC_PLUS_AUTHEN_STATUS_ERROR:
	send_authen_error(session, "Authentication backend failure.");
	return;
    case TAC_PLUS_AUTHEN_STATUS_PASS:
	{
	    char *m = NULL;

	    if (session->passwd_mustchange) {
		session->flag_mavis_auth = 0;
		session->authen_data->authfn = do_chpass;
		do_chpass(session);
		return;
	    }

	    if (session->user->valid_until && session->user->valid_until < io_now.tv_sec + session->ctx->aaa_realm->warning_period)
		m = "\nThis account will expire soon.\n";
	    send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_PASS, set_motd_banner(session, m), 0, NULL, 0, 0);
	    return;
	}
    case TAC_PLUS_AUTHEN_STATUS_FAIL:
	if (resp) {
	    send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_FAIL, resp, 0, NULL, 0, 0);
	    return;
	}
    }

    if (++session->authen_data->iterations <= session->ctx->authen_max_attempts) {
	char *m = (session->user && (session->user->chalresp == TRISTATE_YES)) ? "Response incorrect.\nResponse: " : "Password incorrect.\nPassword: ";
	session->flag_mavis_auth = 0;
	send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_GETPASS, m, 0, NULL, 0, TAC_PLUS_REPLY_FLAG_NOECHO);
    } else {
	char *m = subst_magic(session,
			      (session->user && (session->user->chalresp == TRISTATE_YES)) ? "Response incorrect.\n" : "Password incorrect.\n",
			      session->ctx->authfail_banner, NULL);
	send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_FAIL, m, 0, NULL, 0, 0);
    }
}

static void do_enable_getuser(tac_session * session)
{
    enum pw_ix pw_ix = PW_LOGIN;
    struct pwdat *pwdat = NULL;
    enum hint_enum hint = hint_default;
    char *follow = NULL, *resp = "Password incorrect.\n";
    int res = TAC_PLUS_AUTHEN_STATUS_FAIL;

    if (!session->username[0] && session->authen_data->msg) {
	mem_free(session->mem, &session->username);
	session->username = session->authen_data->msg;
	session->authen_data->msg = NULL;
	session->tag = strchr(session->username, session->ctx->aaa_realm->separator);
	if (session->tag)
	    *session->tag++ = 0;
    }

    if (!session->username[0]) {
	send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_GETUSER, "Username: ", 0, NULL, 0, 0);
	return;
    }

    lookup_and_set_user(session);
    if (query_mavis_info_login(session, do_enable_getuser))
	return;
    set_pwdat(session, &pwdat, &pw_ix);

    if (!pwdat || pwdat->type != S_follow) {

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

	set_taglist(session);

	if (session->user) {
	    pw_ix = PW_LOGIN;
	    set_pwdat(session, &pwdat, &pw_ix);
	}

	if (query_mavis_auth_login(session, do_enable_getuser, pw_ix))
	    return;
    }

    res = check_access(session, pwdat, session->password, &hint, &resp, &follow);

    mem_free(session->mem, &session->challenge);

    report_auth(session, "enforced enable login", hint);

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
    enum hint_enum hint = hint_default;

    lookup_and_set_user(session);
    if (query_mavis_info(session, do_mschap, PW_MSCHAP))
	return;

    if (session->user) {
	set_taglist(session);

	if (session->passwdp->passwd[PW_MSCHAP]->type != S_clear)
	    hint = hint_no_cleartext;
	else if (session->authen_data->data_len == 1 /* PPP id */  + 8 /* challenge length */  + MSCHAP_DIGEST_LEN) {
	    u_char response[24];
	    u_char *chal = session->authen_data->data + 1;
	    u_char *resp = session->authen_data->data + session->authen_data->data_len - MSCHAP_DIGEST_LEN;
	    session->authen_data->data = NULL;

	    if (resp[48]) {
		mschap_ntchalresp(chal, session->passwdp->passwd[PW_MSCHAP]->value, response);
		if (!memcmp(response, resp + 24, 24))
		    res = TAC_PLUS_AUTHEN_STATUS_PASS;
	    } else {
		mschap_lmchalresp(chal, session->passwdp->passwd[PW_MSCHAP]->value, response);
		if (!memcmp(response, resp, 24))
		    res = TAC_PLUS_AUTHEN_STATUS_PASS;
	    }

	    if (res == TAC_PLUS_AUTHEN_STATUS_PASS)
		res = user_invalid(session->user, &hint);
	    if (res == TAC_PLUS_AUTHEN_STATUS_PASS)
		res = cfg_get_access_nas(session, &hint);
	    if (res == TAC_PLUS_AUTHEN_STATUS_PASS)
		res = cfg_get_access_acl(session, &hint);
	} else
	    hint = hint_invalid_challenge_length;
    }

    report_auth(session, "mschap login", hint);

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
    enum hint_enum hint = hint_default;

    lookup_and_set_user(session);
    if (query_mavis_info(session, do_mschapv2, PW_MSCHAP))
	return;

    if (session->user) {
	set_taglist(session);

	if (session->passwdp->passwd[PW_MSCHAP]->type != S_clear)
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

		mschapv2_ntresp(chal, resp, session->user->name, session->passwdp->passwd[PW_MSCHAP]->value, response);
		if (!memcmp(response, resp + 24, 24))
		    res = TAC_PLUS_AUTHEN_STATUS_PASS;
	    }

	    if (res == TAC_PLUS_AUTHEN_STATUS_PASS)
		res = user_invalid(session->user, &hint);
	    if (res == TAC_PLUS_AUTHEN_STATUS_PASS)
		res = cfg_get_access_nas(session, &hint);
	    if (res == TAC_PLUS_AUTHEN_STATUS_PASS)
		res = cfg_get_access_acl(session, &hint);
	} else
	    hint = hint_invalid_challenge_length;
    }

    report_auth(session, "mschapv2 login", hint);

    send_authen_reply(session, res, NULL, 0, NULL, 0, 0);
}
#endif

#ifdef SUPPORT_SENDAUTH
static void do_mschap_out(tac_session * session)
{
    int res = TAC_PLUS_AUTHEN_STATUS_FAIL, data_len = 0;
    u_char digest[MSCHAP_DIGEST_LEN], *data = NULL;
    enum hint_enum hint = hint_default;

    lookup_and_set_user(session);
    if (query_mavis_info(session, do_mschap_out, PW_MSCHAP))
	return;

    if (session->user) {
	if (session->passwdp->passwd[PW_MSCHAP]->type != S_clear)
	    hint = hint_no_cleartext;
	else if (session->authen_data->data_len > 0) {

	    set_taglist(session);
	    res = user_invalid(session->user, &hint);

	    if (res == TAC_PLUS_AUTHEN_STATUS_PASS)
		res = cfg_get_access_nas(session, &hint);
	    if (res == TAC_PLUS_AUTHEN_STATUS_PASS)
		res = cfg_get_access_acl(session, &hint);
	    if (res == TAC_PLUS_AUTHEN_STATUS_PASS) {
		mschap_lmchalresp(session->authen_data->data + 1, session->passwdp->passwd[PW_MSCHAP]->value, digest);
		mschap_ntchalresp(session->authen_data->data + 1, session->passwdp->passwd[PW_MSCHAP]->value, digest + 24);
		digest[MSCHAP_DIGEST_LEN - 1] = 1;
	    }
	}

	if (res == TAC_PLUS_AUTHEN_STATUS_PASS)
	    data = digest, data_len = MSCHAP_DIGEST_LEN;
    }

    report_auth(session, "outbound mschap request", hint);

    send_authen_reply(session, res, NULL, 0, data, data_len, 0);
}
#endif

static void do_login(tac_session * session)
{
    enum pw_ix pw_ix = PW_LOGIN;
    struct pwdat *pwdat = NULL;
    int res = TAC_PLUS_AUTHEN_STATUS_FAIL;
    enum hint_enum hint = hint_default;
    char *follow = NULL, *resp = NULL;

    if (!session->password) {
	session->password = (char *) session->authen_data->data;
	session->authen_data->data = NULL;
	if (password_requirements_failed(session, "ascii login"))
	    return;
    }

    lookup_and_set_user(session);
    if (query_mavis_info_login(session, do_login))
	return;
    set_pwdat(session, &pwdat, &pw_ix);
    set_taglist(session);

    if (query_mavis_auth_login(session, do_login, pw_ix))
	return;

    res = check_access(session, pwdat, session->password, &hint, &resp, &follow);

    report_auth(session, "ascii login", hint);

    send_authen_reply(session, res, resp, 0, NULL, 0, 0);
}

static void do_pap(tac_session * session)
{
    enum pw_ix pw_ix = PW_PAP;
    struct pwdat *pwdat = NULL;
    int res = TAC_PLUS_AUTHEN_STATUS_FAIL;
    enum hint_enum hint = hint_default;
    char *follow = NULL, *resp = NULL;

    if (session->ctx->map_pap_to_login == TRISTATE_YES) {
	do_login(session);
	return;
    }

    if (session->password)
	mem_free(session->mem, &session->password);

    if (session->version != TAC_PLUS_VER_ONE && session->seq_no == 1) {
	send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_GETPASS, "Password: ", 0, NULL, 0, TAC_PLUS_REPLY_FLAG_NOECHO);
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

    lookup_and_set_user(session);
    if (query_mavis_info_pap(session, do_pap))
	return;
    set_pwdat(session, &pwdat, &pw_ix);
    set_taglist(session);

    if (query_mavis_auth_pap(session, do_pap, pw_ix))
	return;

    res = check_access(session, pwdat, session->password, &hint, &resp, &follow);

    report_auth(session, "pap login", hint);

    send_authen_reply(session, res, resp, 0, NULL, 0, 0);
}

#ifdef SUPPORT_SENDAUTH
static void do_pap_out(tac_session * session)
{
    int res = TAC_PLUS_AUTHEN_STATUS_FAIL;
    u_char *data = NULL;
    enum hint_enum hint = hint_default;

    lookup_and_set_user(session);
    if (query_mavis_info(session, do_pap_out, PW_OPAP))
	return;

    if (session->user) {
	set_taglist(session);
	if (session->passwdp->passwd[PW_OPAP]->type != S_clear)
	    hint = hint_no_cleartext;
	else if (TAC_PLUS_AUTHEN_STATUS_PASS == (res = user_invalid(session->user, &hint))) {
	    data = (u_char *) session->passwdp->passwd[PW_OPAP]->value;

	    if (res == TAC_PLUS_AUTHEN_STATUS_PASS)
		res = cfg_get_access_nas(session, &hint);
	    if (res == TAC_PLUS_AUTHEN_STATUS_PASS)
		res = cfg_get_access_acl(session, &hint);
	}
    }

    report_auth(session, "outbound pap request", hint);

    send_authen_reply(session, res, NULL, 0, data, 0, 0);
}
#endif

#ifdef WITH_DNS
static void free_reverse(void *payload, void *data __attribute__((unused)))
{
    free(payload);
}

void add_revmap(struct in6_addr *address, char *hostname)
{
    if (!hostname)
	hostname = "";
    if (!dns_tree_ptr_dynamic[0])
	dns_tree_ptr_dynamic[0] = radix_new(free_reverse, NULL);
    radix_add(dns_tree_ptr_dynamic[0], address, 128, strdup(hostname));
}

static void set_revmap_nac(tac_session * session, char *hostname, int ttl __attribute__((unused)))
{
    report(session, LOG_DEBUG, DEBUG_DNS_FLAG, "NAC revmap(%s) = %s", session->nac_address_ascii, hostname ? hostname : "(not found)");

    if (hostname)
	session->nac_dns_name = mem_strdup(session->mem, hostname);

    session->revmap_pending = 0;
    session->revmap_timedout = 0;

    add_revmap(&session->nac_address, hostname);

    if (!session->ctx->revmap_pending && session->resumefn)
	resume_session(session, -1);
}
#endif

void get_revmap_nac(tac_session * session, tac_host ** arr, int arr_min, int arr_max)
{
    if (
#ifdef WITH_DNS
	   idc &&
#endif
	   session->nac_address_valid) {
	int i, lookup_revmap = session->ctx->nac_realm->lookup_revmap;

	session->dns_timeout = session->ctx->dns_timeout;
	for (i = arr_max; i > arr_min; i--)
	    if (arr[i]->dns_timeout > -1) {
		session->dns_timeout = arr[i]->dns_timeout;
		break;
	    }

	for (i = arr_max; i > arr_min; i--)
	    if (arr[i]->lookup_revmap != TRISTATE_DUNNO) {
		lookup_revmap = arr[i]->lookup_revmap;
		break;
	    }

	if (lookup_revmap == TRISTATE_YES) {
	    char *t = radix_lookup(dns_tree_ptr_static, &session->nac_address, NULL);
#ifdef WITH_DNS
	    if (!t && dns_tree_ptr_dynamic[0])	// current
		t = radix_lookup(dns_tree_ptr_dynamic[0], &session->nac_address, NULL);
	    if (!t && dns_tree_ptr_dynamic[1]) {	// old
		t = radix_lookup(dns_tree_ptr_dynamic[1], &session->nac_address, NULL);
		if (t && *t)
		    radix_add(dns_tree_ptr_dynamic[0], &session->nac_address, 128, strdup(t));
	    }
#endif
	    if (t && *t)
		session->nac_dns_name = mem_strdup(session->mem, t);
#ifdef WITH_DNS
	    else {
		session->revmap_pending = 1;
		report(session, LOG_DEBUG, DEBUG_DNS_FLAG, "Querying NAC revmap (%s)", session->nac_address_ascii);
		io_dns_add_addr(idc, &session->nac_address, (void *) set_revmap_nac, session);
	    }
#endif
	}
    }
}

#ifdef WITH_DNS
static void set_revmap_nas(struct context *ctx, char *hostname, int ttl __attribute__((unused)))
{
    rb_node_t *rbn, *rbnext;

    report(NULL, LOG_DEBUG, DEBUG_DNS_FLAG, "NAS revmap(%s) = %s", ctx->nas_address_ascii, hostname ? hostname : "(not found)");

    if (hostname)
	ctx->nas_dns_name = mem_strdup(ctx->mem, hostname);

    ctx->revmap_pending = 0;
    ctx->revmap_timedout = 0;

    add_revmap(&ctx->nas_address, hostname);

    for (rbn = RB_first(ctx->sessions); rbn; rbn = rbnext) {
	tac_session *session = RB_payload(rbn, tac_session *);
	rbnext = RB_next(rbn);

	if (!session->revmap_pending && session->resumefn)
	    resume_session(session, -1);
    }
}
#endif

void get_revmap_nas(struct context *ctx)
{
    if (
#ifdef WITH_DNS
	   idc &&
#endif
	   ctx->lookup_revmap == TRISTATE_YES) {
	char *t = radix_lookup(dns_tree_ptr_static, &ctx->nas_address, NULL);
#ifdef WITH_DNS
	if (!t && dns_tree_ptr_dynamic[0])	// current
	    t = radix_lookup(dns_tree_ptr_dynamic[0], &ctx->nas_address, NULL);
	if (!t && dns_tree_ptr_dynamic[1]) {	// old
	    t = radix_lookup(dns_tree_ptr_dynamic[1], &ctx->nas_address, NULL);
	    if (t && *t)
		radix_add(dns_tree_ptr_dynamic[0], &ctx->nas_address, 128, strdup(t));
	}
#endif
	if (t && *t)
	    ctx->nas_dns_name = mem_strdup(ctx->mem, t);
#ifdef WITH_DNS
	else {
	    ctx->revmap_pending = 1;
	    report(NULL, LOG_DEBUG, DEBUG_DNS_FLAG, "Querying NAS revmap (%s)", ctx->nas_address_ascii);
	    io_dns_add_addr(idc, &ctx->nas_address, (void *) set_revmap_nas, ctx);
	}
#endif
    }
}

void resume_session(tac_session * session, int cur __attribute__((unused)))
{
    void (*resumefn)(tac_session *) = session->resumefn;
    report(session, LOG_DEBUG, DEBUG_DNS_FLAG, "resuming");
    session->resumefn = NULL;
    if (session->revmap_pending)
	session->revmap_timedout = 1;
    if (session->ctx->revmap_pending)
	session->ctx->revmap_timedout = 1;
    io_sched_del(session->ctx->io, session, (void *) resume_session);
    resumefn(session);
}

void authen(tac_session * session, tac_pak_hdr * hdr)
{
    int username_required = 1;
    struct authen_start *start = tac_payload(hdr, struct authen_start *);
    struct authen_cont *cont = tac_payload(hdr, struct authen_cont *);

    report(session, LOG_DEBUG, DEBUG_AUTHEN_FLAG, "%s: hdr->seq_no: %d", __func__, hdr->seq_no);

    if (!session->authen_data)
	session->authen_data = mem_alloc(session->mem, sizeof(struct authen_data));

    if (hdr->seq_no == 1) {
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
		    if (session->bug_compatibility & CLIENT_BUG_INVALID_START_DATA)
			start->data_len = 0;
		    if (start->user_len && start->data_len) {
			/* PAP-like inbound login. Not in the drafts, but used by IOS-XR. */
			session->authen_data->authfn = do_login;
		    } else {
			/* Standard ASCII login */
			session->authen_data->authfn = do_ascii_login;
			username_required = 0;
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
#ifdef SUPPORT_ARAP
		case TAC_PLUS_AUTHEN_TYPE_ARAP:
		    if (hdr->version == TAC_PLUS_VER_ONE)
			session->authen_data->authfn = do_arap;
		    break;
#endif
#endif
		}
	    }
	    break;
	case TAC_PLUS_AUTHEN_CHPASS:
	    if (session->ctx->aaa_realm->chpass)
		switch (start->type) {
		case TAC_PLUS_AUTHEN_TYPE_ASCII:
		    session->authen_data->authfn = do_chpass;
		    username_required = 0;
		    break;
		}
	    break;
#ifdef SUPPORT_SENDAUTH
	case TAC_PLUS_AUTHEN_SENDAUTH:
	    switch (start->type) {
	    case TAC_PLUS_AUTHEN_TYPE_PAP:
		if (hdr->version == TAC_PLUS_VER_ONE)
		    session->authen_data->authfn = do_pap_out;
		break;
	    case TAC_PLUS_AUTHEN_TYPE_CHAP:
		if (hdr->version == TAC_PLUS_VER_ONE)
		    session->authen_data->authfn = do_chap_out;
		break;
	    case TAC_PLUS_AUTHEN_TYPE_MSCHAP:
		if (hdr->version == TAC_PLUS_VER_ONE)
		    session->authen_data->authfn = do_mschap_out;
		break;
	    }
	    break;
#endif
	}

	if (session->authen_data->authfn) {
	    u_char *p = (u_char *) start + TAC_AUTHEN_START_FIXED_FIELDS_SIZE;
	    session->username = mem_strndup(session->mem, p, start->user_len);

	    session->tag = strchr(session->username, session->ctx->aaa_realm->separator);
	    if (session->tag)
		*session->tag++ = 0;
	    p += start->user_len;
	    session->nas_port = mem_strndup(session->mem, p, start->port_len);
	    p += start->port_len;
	    session->nac_address_ascii = mem_strndup(session->mem, p, start->rem_addr_len);
	    p += start->rem_addr_len;
	    session->authen_data->data = (u_char *) mem_strndup(session->mem, p, start->data_len);
	    session->authen_data->data_len = start->data_len;

	    session->nac_address_valid = v6_ptoh(&session->nac_address, NULL, session->nac_address_ascii) ? 0 : 1;

	    if (S_permit != eval_host_acl(session)) {
		report_auth(session, "authentication request", hint_rejected);

		send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_FAIL, subst_magic(session, session->ctx->reject_banner, NULL), 0, NULL, 0, 0);
		return;
	    }

	    session->priv_lvl = start->priv_lvl;
	    if (session->priv_lvl & ~0xf) {
		send_authen_error(session, "Invalid privilege level %d in packet.", session->priv_lvl);
		return;
	    }

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
#ifdef SUPPORT_FOLLOW
		    for (i = arr_max; i > arr_min; i--)
			if (arr[i]->follow) {
			    send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_FOLLOW, NULL, 0, (u_char *) arr[i]->follow, 0, 0);
			    return;
			}
#endif
		    get_revmap_nac(session, arr, arr_min, arr_max);
		}
	    }
	}
    } else if (cont->flags & TAC_PLUS_CONTINUE_FLAG_ABORT) {
	char *t = hints[hint_abort].plain;
	size_t l = ntohs(cont->user_data_len) + 100;
	char *tmp = alloca(l);
	if (cont->user_data_len) {
	    snprintf(tmp, l, "%s (%*s)", t, cont->user_msg_len, (char *) cont + TAC_AUTHEN_CONT_FIXED_FIELDS_SIZE + ntohs(cont->user_msg_len));
	    t = tmp;
	}
	report_auth(session, t, hint_abort);
	cleanup_session(session);
	return;
    } else {			/* hdr->seq_no != 1 */
	username_required = 0;
	mem_free(session->mem, &session->authen_data->msg);
	mem_free(session->mem, &session->authen_data->data);
	session->authen_data->msg = mem_strndup(session->mem, (u_char *) cont + TAC_AUTHEN_CONT_FIXED_FIELDS_SIZE, ntohs(cont->user_msg_len));
	session->authen_data->msg_len = ntohs(cont->user_msg_len);
	session->authen_data->data = (u_char *)
	    mem_strndup(session->mem, (u_char *) cont + TAC_AUTHEN_CONT_FIXED_FIELDS_SIZE + ntohs(cont->user_msg_len), ntohs(cont->user_data_len));
	session->authen_data->data_len = ntohs(cont->user_data_len);
    }

    if (session->authen_data->authfn) {
	if (username_required && !session->username[0])
	    send_authen_error(session, "No username in packet");
	else {
#ifdef WITH_DNS
	    if ((hdr->seq_no == 1) && (session->dns_timeout > 0) && (session->revmap_pending || session->ctx->revmap_pending)) {
		session->resumefn = session->authen_data->authfn;
		io_sched_add(session->ctx->io, session, (void *) resume_session, session->dns_timeout, 0);
	    } else
#endif
		session->authen_data->authfn(session);
	}
    } else
	send_authen_error(session, "Invalid or unsupported AUTHEN/START " "(action=%d authen_type=%d)", start->action, start->type);
}

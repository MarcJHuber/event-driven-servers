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
#include "misc/utf.h"

#if defined(WITH_CRYPTO)
#if OPENSSL_VERSION_NUMBER < 0x30000000
#include <openssl/sha.h>
#else
#include <openssl/types.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
OSSL_PROVIDER *ossl_legacy = NULL;
OSSL_PROVIDER *ossl_default = NULL;
#endif
#endif

#define DEBAUTHC session, LOG_DEBUG, DEBUG_AUTHEN_FLAG

static const char rcsid[] __attribute__((used)) = "$Id$";

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
static struct log_item *li_password_changed = NULL;
static struct log_item *li_motd_dflt = NULL;
static struct log_item *li_change_password = NULL;
static struct log_item *li_enable_password_incorrect = NULL;
static struct log_item *li_password_incorrect_retry = NULL;
static struct log_item *li_password_incorrect = NULL;
static struct log_item *li_response_incorrect_retry = NULL;
static struct log_item *li_response_incorrect = NULL;
static struct log_item *li_account_expires = NULL;
static struct log_item *li_password_expires = NULL;
static struct log_item *li_password_expired = NULL;
struct log_item *li_denied_by_acl = NULL;

struct hint_struct {
    str_t plain;
    str_t msgid;
};

#define HINT(A,B) { { A, sizeof(A) - 1 }, { B, sizeof(B) - 1} }

static struct hint_struct hints[hint_max] = {
    HINT("failed", "AUTHC-FAIL"),
    HINT("failed (denied)", "AUTHC-FAIL-DENY"),
    HINT("failed (password not set)", "AUTHC-FAIL-NOPASS"),
    HINT("failed (expired)", "AUTHC-FAIL-EXPIRED"),
    HINT("failed (no such user)", "AUTHC-FAIL-NOUSER"),
    HINT("succeeded", "AUTHC-PASS"),
    HINT("succeeded (permitted)", "AUTHC-PASS-PERMIT"),
    HINT("failed (no clear text password set)", "AUTHC-FAIL-PASSWORD-NOT-TEXT"),
    HINT("failed (backend error)", "AUTHC-FAIL-BACKEND"),
    HINT("denied by user profile", "AUTHC-FAIL-USERPROFILE"),
    HINT("failed (retry with identical password)", "AUTHC-FAIL-DENY-RETRY"),
    HINT("failed (This might be a bug, consider reporting it!)", "AUTHC-FAIL-BUG"),
    HINT("aborted by request", "AUTHC-FAIL-ABORT"),
    HINT("denied by ACL", "AUTHC-FAIL-ACL"),
    HINT("denied (invalid challenge length)", "AUTHC-FAIL-BAD-CHALLENGE-LENGTH"),
    HINT("denied (minimum password requirements not met)", "AUTHC-FAIL-WEAKPASSWORD"),
    HINT("denied (bad RADIUS secret)", "AUTHC-FAIL-BADSECRET"),
    HINT("error (rejected)", "AUTHC-ERROR"),
};

#undef HINT

#define TAC_SYM_TO_CODE(A) (((A) == S_permit) ? TAC_PLUS_AUTHEN_STATUS_PASS : TAC_PLUS_AUTHEN_STATUS_FAIL)
#define RAD_SYM_TO_CODE(A) (((A) == S_permit) ? RADIUS_CODE_ACCESS_ACCEPT : RADIUS_CODE_ACCESS_REJECT)

static char *get_hint(tac_session *session, enum hint_enum h)
{
    if (session->user_msg.txt) {
	size_t n = hints[h].plain.len + session->user_msg.len + 20;
	char *hint = mem_alloc(session->mem, n);
	strcpy(hint, hints[h].plain.txt);
	strcat(hint, " [");
	strcat(hint, session->user_msg.txt);
	char *t = strchr(hint, '\n');
	if (t)
	    strcpy(t, "]");
	else
	    strcat(hint, "]");
	return hint;
    }
    return hints[h].plain.txt;
}

static void report_auth(tac_session *session, char *what, enum hint_enum hint, enum token res)
{
    char *realm = alloca(session->ctx->realm->name.len + 40);
    tac_realm *r = session->ctx->realm;

    session->result = &codestring[res];

    if (r == config.default_realm)
	*realm = 0;
    else {
	strcpy(realm, " (realm: ");
	strcat(realm, session->ctx->realm->name.txt);
	strcat(realm, ")");
    }

    char *hint_augmented = get_hint(session, hint);

#define IS_SET(A) (A && A[0])
    report(session, LOG_INFO_AUTH, ~0,
	   "%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
	   what,
	   IS_SET(session->username.txt) ? " for '" : "", session->username.txt,
	   IS_SET(session->username.txt) ? "'" : "", realm,
	   IS_SET(session->nac_addr_ascii.txt) ? " from " : "",
	   IS_SET(session->nac_addr_ascii.txt) ? session->nac_addr_ascii.txt : "",
	   IS_SET(session->port.txt) ? " on " : "",
	   IS_SET(session->port.txt) ? session->port.txt : "",
	   hint_augmented ? " " : "", hint_augmented,
	   session->profile ? " (profile=" : "", session->profile ? session->profile->name.txt : "", session->profile ? ")" : "");
#undef IS_SET

    session->msgid = &hints[hint].msgid;
    str_set(&session->action, what, 0);
    str_set(&session->hint, hint_augmented, 0);

    log_exec(session, session->ctx, session->radius_data ? S_radius_access : S_authentication, io_now.tv_sec);
}

static int password_requirements_failed(tac_session *session, char *what)
{
    tac_realm *r = session->ctx->realm;

    if (r->password_acl) {
	u_int debug = session->debug;
	if (!(session->debug & DEBUG_USERINPUT_FLAG))
	    session->debug = 0;
	enum token token = eval_tac_acl(session, r->password_acl);
	session->debug = debug;
	if (token != S_permit) {
	    report(session, LOG_ERR, ~0, "password doesn't meet minimum requirements");
	    report_auth(session, what, hint_weak_password, S_deny);
	    char *msg = eval_log_format(session, session->ctx, NULL, li_password_minreq, io_now.tv_sec, NULL);
	    if (session->ctx->aaa_protocol == S_tacacs_tcp || session->ctx->aaa_protocol == S_tacacs_tls)
		send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_FAIL, msg, 0, NULL, 0, 0);
	    else		// radius
		rad_send_authen_reply(session, RADIUS_CODE_ACCESS_REJECT, msg);
	    return -1;
	}
    }
    return 0;
}

static int user_invalid(tac_user *user, enum hint_enum *hint)
{
    int res = (user->valid_from && user->valid_from > io_now.tv_sec) || (user->valid_until && user->valid_until <= io_now.tv_sec);
    if (res && hint)
	*hint = hint_expired;
    return res ? S_deny : S_permit;
}

#ifdef WITH_SSL
static size_t base64_decode(const char *base64, size_t len, unsigned char *output)
{
    BIO *bio = BIO_new_mem_buf(base64, len);
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);
    size_t decoded_len = BIO_read(bio, output, len);
    BIO_free_all(bio);
    return decoded_len;
}

static int verify_cisco_asa_pbkdf2(char *password, char *p)
{
    if (strncmp(p, "$sha512$", 8))
	return -1;
    p += 8;
    int iterations = 0;
    while (*p && *p >= '0' && *p <= '9') {
	iterations *= 10;
	iterations += *p++ - '0';
    }
    if (!iterations || *p++ != '$')
	return -1;

    char *salt_base64 = p;
    while (*p && *p != '$')
	p++;
    if (*p != '$')
	return -1;
    size_t salt_base64_len = p++ - salt_base64;
    if (!salt_base64_len)
	return -1;

    char *hash_base64 = p;
    while (*p)
	p++;
    size_t hash_base64_len = p - hash_base64;
    if (!hash_base64_len)
	return -1;

    unsigned char salt[salt_base64_len];
    size_t salt_len = base64_decode(salt_base64, salt_base64_len, salt);
    if (salt_len != 16)
	return -1;

    unsigned char stored_hash[hash_base64_len];
    size_t hash_len = base64_decode(hash_base64, hash_base64_len, stored_hash);
    if (hash_len != 16)
	return -1;

    unsigned char computed_hash[64];
    PKCS5_PBKDF2_HMAC(password, strlen(password), salt, salt_len, iterations, EVP_sha512(), 64, computed_hash);

    return memcmp(computed_hash, stored_hash, 16);
}

static void cisco64_enc(const unsigned char *in, size_t in_len, char *out)
{
    char *h64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    char *outp = out;
    size_t bitcount = 0;
    uint64_t bits = 0;
    while (in_len) {
	while (in_len && (bitcount <= 8 * sizeof(bits) - 8)) {
	    bitcount += 8;
	    bits |= (((uint64_t) * in) << (8 * sizeof(bits) - bitcount));
	    in++, in_len--;
	}
	while (bitcount > 5) {
	    *outp++ = h64[bits >> (8 * sizeof(bits) - 6)];
	    bitcount -= 6;
	    bits <<= 6;
	}
    }
    if (bitcount)
	*outp++ = h64[bits >> (8 * sizeof(bits) - 6)];
    *outp = 0;
}

static int verify_cisco_type4(char *hash_in, char *password)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *) password, strlen(password), hash);
    char hash64[128];
    cisco64_enc(hash, SHA256_DIGEST_LENGTH, hash64);
    return strcmp(hash64, hash_in);
}

static int verify_cisco_type89(char *password, char *p, char type)
{
    if (p[0] != '$' || p[1] != type || p[2] != '$')
	return -1;
    p += 3;
    unsigned char *salt = (unsigned char *) p;
    size_t salt_len = 0;
    while (*p && *p != '$')
	p++, salt_len++;
    if (!*p)
	return -1;
    p++;
    char *hash_in = p;
    size_t hash_in_len = 0;
    while (*p)
	p++, hash_in_len++;
    unsigned char hash[32];
    if (type == '8') {
	if (!PKCS5_PBKDF2_HMAC(password, strlen(password), salt, salt_len, 20000, EVP_sha256(), 32, hash))
	    return -1;
    } else if (type == '9') {
#ifdef OPENSSL_NO_SCRYPT
	report(NULL, LOG_INFO, ~0, "%s doesn't support Type 9 (scrypt) passwords", OPENSSL_VERSION_TEXT);
	return -1;
#else
	if (!EVP_PBE_scrypt(password, strlen(password), salt, salt_len, 16384, 1, 1, 0, hash, 32))
	    return -1;
#endif
    }
    char hash64[128];
    cisco64_enc(hash, 32, hash64);
    return strcmp(hash64, hash_in);
}
#endif

static int verify_cisco_asa_md5(const char *username, const char *password, const char *hash_in)
{
    char buf[33] = { 0 };
    char *bufp = stpncpy(buf, password, sizeof(buf));
    if (username && *username && (bufp - buf < 28)) {
	char *e = bufp + 4;
	while (bufp < e)
	    bufp = stpncpy(bufp, username, e - bufp);
    }
    u_char digest[MD5_LEN];
    struct iovec iov = {.iov_base = buf,.iov_len = (bufp - buf > 16) ? 32 : 16 };
    md5v(digest, MD5_LEN, &iov, 1);

    char *h64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    char hash64[32];
    char *h = hash64;
    for (int i = 0; i < 16; i += 4) {
	uint32_t v = digest[i] | (digest[i + 1] << 8) | (digest[i + 2] << 16);
	for (int j = 0; j < 4; j++) {
	    *h++ = h64[v & 0x3f];
	    v >>= 6;
	}
    }
    *h = 0;

    return strcmp(hash64, hash_in);
}

static enum token compare_pwdat(struct pwdat *a, char *username __attribute__((unused)), char *b, enum hint_enum *hint)
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
	    else {
		char *c = crypt(b, a->value);
		if (c)
		    res = strcmp(a->value, c);
	    }
	}
	break;
#ifdef WITH_SSL
    case S_pbkdf2:
	if (b)
	    res = verify_cisco_asa_pbkdf2(b, a->value);
	break;
    case S_4:
	if (b)
	    res = verify_cisco_type4(b, a->value);
	break;
    case S_8:
	if (b)
	    res = verify_cisco_type89(b, a->value, '8');
	break;
    case S_9:
	if (b)
	    res = verify_cisco_type89(b, a->value, '9');
	break;
#endif
    case S_asa:
	if (b)
	    res = verify_cisco_asa_md5(username, b, a->value);
	break;
    case S_permit:
	*hint = hint_permitted;
	return S_permit;
    case S_deny:
	*hint = hint_denied;
	return S_deny;
    case S_error:
	*hint = hint_error;
	return S_error;
    case S_unknown:
	*hint = hint_nopass;
	return S_deny;
    default:
	*hint = hint_bug;
	return S_deny;
    }

    if (res) {
	*hint = hint_failed;
	return S_deny;
    }

    *hint = hint_succeeded;
    return S_permit;
}

static enum token lookup_and_set_user(tac_session *session)
{
    enum token res = S_unknown;
    tac_host *h = session->ctx->host;
    while (res != S_permit && res != S_deny && h) {
	if (h->action) {
	    res = tac_script_eval_r(session, h->action);
	    switch (res) {
	    case S_deny:
		report(DEBAUTHC, "user %s realm %s denied by ACL", session->username.txt, session->ctx->realm->name.txt);
		report_auth(session, "session", hint_denied_by_acl, S_deny);
		return S_deny;
	    default:
		break;
	    }
	}
	h = h->parent;
    }

    report(DEBAUTHC, "looking for user %s realm %s", session->username.txt, session->ctx->realm->name.txt);

    if (!session->user_is_session_specific)
	session->user = lookup_user(session);

    if (session->user && session->user->fallback_only
	&& ((session->ctx->realm->last_backend_failure + session->ctx->realm->backend_failure_period < io_now.tv_sec)
	    || (session->ctx->host->authfallback != TRISTATE_YES))) {
	session->user = NULL;
	res = S_deny;
    }

    if (session->user && session->user->rewritten_only && !session->username_rewritten) {
	report(DEBAUTHC, "Login for user %s is prohibited", session->user->name.txt);
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

    report(DEBAUTHC, "user lookup %s", (res == S_permit) ? "succeded" : "failed");
    return res;
}

static int query_mavis_auth_login(tac_session *session, void (*f)(tac_session *), enum pw_ix pw_ix)
{
    int res = !session->flag_mavis_auth
	&& ((!session->user &&(session->ctx->realm->mavis_login == TRISTATE_YES) &&(session->ctx->realm->mavis_login_prefetch != TRISTATE_YES))
	    || (session->user && pw_ix == PW_MAVIS));
    session->flag_mavis_auth = 1;
    if (res)
	mavis_lookup(session, f, AV_V_TACTYPE_AUTH, PW_LOGIN);
    if (session->password_expiry > -1) {
	char *m = NULL;
	size_t m_len = 0;
	if (io_now.tv_sec > session->password_expiry)
	    m = eval_log_format(session, session->ctx, NULL, li_password_expired, io_now.tv_sec, &m_len);
	else if (io_now.tv_sec + session->ctx->host->password_expiry_warning > session->password_expiry)
	    m = eval_log_format(session, session->ctx, NULL, li_password_expires, io_now.tv_sec, &m_len);
	if (m && strchr(m, (int) '%')) {
	    struct tm *tm = localtime(&session->password_expiry);
	    size_t b_len = m_len + 200;
	    char *b = alloca(b_len);
	    if (strftime(b, b_len, m, tm))
		m = mem_strdup(session->mem, b);
	}
	if (m)
	    str_set(&session->user_msg, m, 0);
    }
    return res;
}

static int query_mavis_info_login(tac_session *session, void (*f)(tac_session *))
{
    int res = !session->flag_mavis_info && !session->user &&(session->ctx->realm->mavis_login_prefetch == TRISTATE_YES);
    session->flag_mavis_info = 1;
    if (res)
	mavis_lookup(session, f, AV_V_TACTYPE_INFO, PW_LOGIN);
    return res;
}

int query_mavis_info(tac_session *session, void (*f)(tac_session *), enum pw_ix pw_ix)
{
    int res = !session->flag_mavis_info && !session->user;
    session->flag_mavis_info = 1;
    if (res)
	mavis_lookup(session, f, AV_V_TACTYPE_INFO, pw_ix);
    return res;
}

static int query_mavis_auth_pap(tac_session *session, void (*f)(tac_session *), enum pw_ix pw_ix)
{
    int res = !session->flag_mavis_auth &&
	((!session->user && (session->ctx->realm->mavis_pap == TRISTATE_YES) && (session->ctx->realm->mavis_pap_prefetch != TRISTATE_YES))
	 || (session->user && pw_ix == PW_MAVIS));
    session->flag_mavis_auth = 1;
    if (res)
	mavis_lookup(session, f, AV_V_TACTYPE_AUTH, PW_PAP);
    return res;
}

static int query_mavis_info_pap(tac_session *session, void (*f)(tac_session *))
{
    int res = !session->user && (session->ctx->realm->mavis_pap_prefetch == TRISTATE_YES) && !session->flag_mavis_info;
    session->flag_mavis_info = 1;
    if (res)
	mavis_lookup(session, f, AV_V_TACTYPE_INFO, PW_PAP);
    return res;
}

int query_mavis_dacl(tac_session *session, void (*f)(tac_session *))
{
    int res = !session->flag_mavis_info && !session->radius_data->dacl;
    session->flag_mavis_info = 1;
    if (res)
	mavis_dacl_lookup(session, f, AV_V_TACTYPE_DACL);
    return res;
}

static enum token check_access(tac_session * session, struct pwdat *pwdat, char *passwd, enum hint_enum *hint, char **resp);

static void do_chap(tac_session *session)
{
    enum token res = S_deny;

    if (S_deny == lookup_and_set_user(session)) {
	report_auth(session, "chap login", hint_denied_by_acl, S_deny);
	send_authen_reply(session, res, NULL, 0, NULL, 0, 0);
	return;
    }

    if (query_mavis_info(session, do_chap, PW_CHAP))
	return;

    enum hint_enum hint = hint_nosuchuser;
    if (session->user) {
	res = user_invalid(session->user, &hint);
	if (res == S_permit) {
	    if (session->user->passwd[PW_CHAP]->type != S_clear) {
		hint = hint_no_cleartext;
		report_auth(session, "chap login", hint, res);
		send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_RESTART, NULL, 0, NULL, 0, 0);
		return;
	    }
	    if (session->authen_data->data_len - MD5_LEN > 0) {
		u_char digest[MD5_LEN];
		struct iovec iov[3] = {
		    {.iov_base = session->authen_data->data,.iov_len = 1 },
		    {.iov_base = session->user->passwd[PW_CHAP]->value,.iov_len = strlen(session->user->passwd[PW_CHAP]->value) },
		    {.iov_base = session->authen_data->data + 1,.iov_len = session->authen_data->data_len - 1 - MD5_LEN },
		};
		md5v(digest, MD5_LEN, iov, 3);

		if (memcmp(digest, session->authen_data->data + session->authen_data->data_len - MD5_LEN, (size_t) MD5_LEN)) {
		    res = S_deny;
		    hint = hint_failed;
		} else {
		    char *resp = NULL;
		    session->mavisauth_res = S_permit;
		    res = check_access(session, NULL, session->user->passwd[PW_CHAP]->value, &hint, &resp);
		}
	    }
	}
    }

    report_auth(session, "chap login", hint, res);

    send_authen_reply(session, TAC_SYM_TO_CODE(res), NULL, 0, NULL, 0, 0);
}

static enum token check_access(tac_session *session, struct pwdat *pwdat, char *passwd, enum hint_enum *hint, char **resp)
{
    enum token res = S_deny;

    if (session->mavisauth_res != S_unknown) {
	res = session->mavisauth_res;
	session->mavisauth_res = S_unknown;
	if (res == S_error && session->ctx->host->authfallback != TRISTATE_YES)
	    res = S_deny;
    } else if (pwdat)
	res = compare_pwdat(pwdat, session->username.txt, passwd, hint);

    switch (res) {
    case S_permit:
	*hint = hint_succeeded;
	break;
    case S_error:
	if (pwdat && pwdat->type == S_error)
	    *hint = hint_error;
	else
	    *hint = hint_backend_error;
	break;
    default:
	*hint = hint_failed;
	break;
    }

    if (session->user && (!pwdat || pwdat->type != S_error)) {
	if (res == S_permit && !session->authorized &&
	    (S_deny == author_eval_host(session, session->ctx->host, session->ctx->realm->script_host_parent_first) ||
	     S_permit != eval_ruleset(session, session->ctx->realm))) {
	    res = S_deny;
	    *hint = hint_denied_by_acl;
	}

	session->password_bad = NULL;
	if (res == S_permit)
	    res = user_invalid(session->user, hint);

	if (res != S_permit) {
	    if (session->ctx->host->reject_banner)
		*resp = eval_log_format(session, session->ctx, NULL, session->ctx->host->reject_banner, io_now.tv_sec, NULL);
	    session->password_bad = session->password;
	    session->password = NULL;
	}
    }

    if (!*resp)
	*resp = session->user_msg.txt;

    return res;
}

static void set_pwdat(tac_session *session, struct pwdat **pwdat, enum pw_ix *pw_ix)
{
    if (session->user) {
	if (!session->user->fallback_only && (session->ctx->realm->last_backend_failure + session->ctx->realm->backend_failure_period > io_now.tv_sec)
	    && session->ctx->host->authfallback == TRISTATE_YES) {
	    if (*pw_ix == PW_LOGIN) {
		*pw_ix = PW_LOGIN_FALLBACK;
		session->mavisauth_res = S_unknown;
	    } else if (*pw_ix == PW_PAP) {
		*pw_ix = PW_PAP_FALLBACK;
		session->mavisauth_res = S_unknown;
	    }
	}

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

static char *set_welcome_banner(tac_session *session, struct log_item *fmt_dflt)
{
    if (session->welcome_banner)
	return session->msg.txt;

    struct log_item *fmt = ((session->ctx->host->authfallback != TRISTATE_YES)
			    || !session->ctx->host->welcome_banner_fallback
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

static char *set_motd_banner(tac_session *session)
{
    struct log_item *fmt = session->ctx->host->motd;

    if (!fmt)
	fmt = li_motd_dflt;

    if (session->motd || (session->user->hushlogin == TRISTATE_YES)
	|| (session->user->hushlogin == TRISTATE_DUNNO && session->profile && session->profile->hushlogin == TRISTATE_YES)) {
	session->motd = session->user_msg.txt;
	return NULL;
    }

    session->motd = eval_log_format(session, session->ctx, NULL, fmt, io_now.tv_sec, NULL);
    return session->motd;
}

static void do_chpass(tac_session *session)
{
    enum hint_enum hint = hint_nosuchuser;

    if (!session->username.txt[0] && session->authen_data->msg) {
	mem_free(session->mem, &session->username);
	str_set(&session->username, session->authen_data->msg, session->authen_data->msg_len);
	session->authen_data->msg = NULL;
    }
    if (!session->username.txt[0]) {
	session->msg.txt = eval_log_format(session, session->ctx, NULL, li_username, io_now.tv_sec, &session->msg.len);
	send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_GETUSER, set_welcome_banner(session, li_user_access_verification), 0, NULL, 0, 0);
	str_set(&session->msg, NULL, 0);
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
	str_set(&session->user_msg, NULL, 0);
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
	str_set(&session->user_msg, NULL, 0);
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

    enum token res = lookup_and_set_user(session);
    if (res == S_deny) {
	report_auth(session, "password change", hint_denied_by_acl, S_deny);
	send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_FAIL, NULL, 0, NULL, 0, 0);
	return;
    }

    if (query_mavis_info_login(session, do_chpass))
	return;

    enum pw_ix pw_ix = PW_LOGIN;
    struct pwdat *pwdat = NULL;
    set_pwdat(session, &pwdat, &pw_ix);

    if (!session->flag_mavis_auth
	&& (((session->ctx->realm->mavis_login_prefetch != TRISTATE_YES) && !session->user) || (session->user && pw_ix == PW_MAVIS))) {
	session->flag_mavis_auth = 1;
	mavis_lookup(session, do_chpass, AV_V_TACTYPE_CHPW, PW_LOGIN);
	return;
    }

    char *resp = NULL;
    res = check_access(session, pwdat, session->password_new, &hint, &resp);

    if (res == S_permit) {
	session->passwd_mustchange = 0;
	if (resp) {
	    str_set(&session->user_msg, resp, 0);
	} else
	    session->user_msg.txt = eval_log_format(session, session->ctx, NULL, li_password_changed, io_now.tv_sec, &session->user_msg.len);
	resp = set_motd_banner(session);
    }

    report_auth(session, "password change", hint, res);

    send_authen_reply(session, TAC_SYM_TO_CODE(res), resp, 0, NULL, 0, 0);
}

static void send_password_prompt(tac_session *session, enum pw_ix pw_ix, void (*f)(tac_session *))
{
    if ((session->ctx->realm->chalresp == TRISTATE_YES) && (!session->user || ((pw_ix == PW_MAVIS) && (TRISTATE_NO != session->user->chalresp)))) {
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
	    strcat(chal, "\n");
	    strcat(chal, eval_log_format(session, session->ctx, NULL, li_response, io_now.tv_sec, &session->msg.len));
	    strcat(chal, " ");
	    str_set(&session->msg, chal, 0);
	    session->welcome_banner = set_welcome_banner(session, NULL);
	    send_authen_reply(session,
			      TAC_PLUS_AUTHEN_STATUS_GETPASS, session->welcome_banner, 0, NULL, 0,
			      (session->ctx->realm->chalresp_noecho == TRISTATE_YES) ? TAC_PLUS_REPLY_FLAG_NOECHO : 0);
	    str_set(&session->msg, NULL, 0);
	    return;
	}
    }

    session->msg.txt = eval_log_format(session, session->ctx, NULL, li_password, io_now.tv_sec, &session->msg.len);
    session->welcome_banner = set_welcome_banner(session, li_user_access_verification);
    str_set(&session->msg, NULL, 0);

    send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_GETPASS, session->welcome_banner, 0, NULL, 0, TAC_PLUS_REPLY_FLAG_NOECHO);
}

/* enable with login password */
static void do_enable_login(tac_session *session)
{
    enum hint_enum hint = hint_nosuchuser;
    char *resp = eval_log_format(session, session->ctx, NULL, li_permission_denied, io_now.tv_sec, NULL);

    enum token res = lookup_and_set_user(session);
    if (res == S_deny) {
	report_auth(session, "enable login", hint_denied_by_acl, res);
	send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_FAIL, NULL, 0, NULL, 0, 0);
	return;
    }

    if (session->user && session->user->passwd[PW_LOGIN] && session->user->passwd[PW_LOGIN]->type == S_error) {
	send_authen_error(session, "Handling refused.");
	return;
    }

    if (query_mavis_info_login(session, do_enable_login))
	return;

    char buf[40];
    snprintf(buf, sizeof(buf), "enable %d", session->priv_lvl);

    enum pw_ix pw_ix = PW_LOGIN;
    struct pwdat *pwdat = NULL;
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

    set_pwdat(session, &pwdat, &pw_ix);

    res = check_access(session, pwdat, session->password, &hint, &resp);

    report_auth(session, buf, hint, res);

    send_authen_reply(session, TAC_SYM_TO_CODE(res), (res == S_permit) ? NULL : resp, 0, NULL, 0, 0);
}

static void do_enable_getuser(tac_session *);

static void do_enable_augmented(tac_session *session)
{
    enum hint_enum hint = hint_denied;
    char *u;
    char *resp = eval_log_format(session, session->ctx, NULL, li_permission_denied, io_now.tv_sec, NULL);

    enum token res = lookup_and_set_user(session);
    if (res == S_deny) {
	report_auth(session, "enable login", hint_denied_by_acl, res);
	send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_FAIL, NULL, 0, NULL, 0, 0);
	return;
    }

    if (session->user && session->user->passwd[PW_LOGIN] && session->user->passwd[PW_LOGIN]->type == S_error) {
	send_authen_error(session, "Handling refused.");
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
	    session->username.txt = session->authen_data->msg;
	    session->username.len = u - session->authen_data->msg;
	    *u++ = 0;
	    session->password = u;
	    session->authen_data->msg = NULL;
	    if (password_requirements_failed(session, "enable login"))
		return;
	    res = lookup_and_set_user(session);
	    if (res == S_deny) {
		report_auth(session, "enable login", hint_denied_by_acl, res);
		send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_FAIL, NULL, 0, NULL, 0, 0);
		return;
	    }
	}
    }

    enum pw_ix pw_ix = PW_LOGIN;
    struct pwdat *pwdat = NULL;
    set_pwdat(session, &pwdat, &pw_ix);

    if (session->username.txt[0]) {
	if (query_mavis_auth_login(session, do_enable_augmented, pw_ix))
	    return;

	set_pwdat(session, &pwdat, &pw_ix);

	cfg_get_enable(session, &session->enable);

	if (session->enable) {
	    if (session->enable->type == S_login)
		res = check_access(session, pwdat, session->password, &hint, &resp);
	}
    }

    report_auth(session, "enable login", hint, res);

    send_authen_reply(session, TAC_SYM_TO_CODE(res), (res == S_permit) ? NULL : resp, 0, NULL, 0, 0);
}

static void do_enable(tac_session *session)
{
    enum token res = S_deny;
    enum hint_enum hint = hint_denied;

    if ((session->ctx->host->augmented_enable == TRISTATE_YES) && (S_permit == eval_tac_acl(session, session->ctx->realm->enable_user_acl))
	) {
	session->username.txt[0] = 0;
	session->authfn = do_enable_augmented;
	do_enable_augmented(session);
	return;
    }

    if ((!session->username.txt[0] || (S_permit == eval_tac_acl(session, session->ctx->realm->enable_user_acl)))
	&& !session->enable_getuser && (session->ctx->host->anon_enable == TRISTATE_NO)) {
	session->enable_getuser = 1;
	session->username.txt[0] = 0;
	session->authfn = do_enable_getuser;
	do_enable_getuser(session);
	return;
    }

    char buf[40];
    if (S_deny == lookup_and_set_user(session)) {
	snprintf(buf, sizeof(buf), "enable %d", session->priv_lvl);
	report_auth(session, buf, hint_denied_by_acl, res);
	send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_FAIL, NULL, 0, NULL, 0, 0);
	return;
    }

    if (session->user && session->user->passwd[PW_LOGIN] && session->user->passwd[PW_LOGIN]->type == S_error) {
	send_authen_error(session, "Handling refused.");
	return;
    }

    if (query_mavis_info(session, do_enable, PW_LOGIN))
	return;


    if (!session->enable)
	cfg_get_enable(session, &session->enable);

    if (session->enable && session->enable_getuser && (session->enable->type == S_permit))
	res = S_permit;
    else {
	if (session->user && session->enable && (session->enable->type == S_login)) {
	    session->authfn = do_enable_login;
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
	    res = compare_pwdat(session->enable, session->username.txt, session->authen_data->msg, &hint);
    }

    snprintf(buf, sizeof(buf), "enable %d", session->priv_lvl);

    report_auth(session, buf, hint, res);

    send_authen_reply(session, TAC_SYM_TO_CODE(res),
		      (res == S_permit) ? NULL : eval_log_format(session, session->ctx, NULL, li_permission_denied, io_now.tv_sec, NULL), 0, NULL, 0, 0);
}

static void do_ascii_login(tac_session *session)
{
    enum hint_enum hint = hint_nosuchuser;
    char *resp = NULL, *m;
    enum token res = S_deny;

    if (!session->username.txt[0] && session->authen_data->msg) {
	mem_free(session->mem, &session->username);
	session->username.txt = session->authen_data->msg;
	session->username.len = session->authen_data->msg_len;
	session->authen_data->msg = NULL;
    }

    if (!session->username.txt[0]) {
	session->msg.txt = eval_log_format(session, session->ctx, NULL, li_username, io_now.tv_sec, &session->msg.len);
	send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_GETUSER, set_welcome_banner(session, li_user_access_verification), 0, NULL, 0, 0);
	str_set(&session->msg, NULL, 0);
	return;
    }

    if (S_deny == lookup_and_set_user(session)) {
	report_auth(session, "shell login", hint_denied_by_acl, res);
	send_authen_reply(session, res, NULL, 0, NULL, 0, 0);
	return;
    }

    if (session->user && session->user->passwd[PW_LOGIN] && session->user->passwd[PW_LOGIN]->type == S_error) {
	send_authen_error(session, "Handling refused.");
	return;
    }

    if (query_mavis_info_login(session, do_ascii_login))
	return;

    enum pw_ix pw_ix = PW_LOGIN;
    struct pwdat *pwdat = NULL;
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
	    mem_free(session->mem, &session->password);
	    session->password = NULL;
	    session->authfn = do_chpass;
	    session->flag_mavis_auth = 0;
	    session->user_msg.txt = eval_log_format(session, session->ctx, NULL, li_password_change_dialog, io_now.tv_sec, &session->user_msg.len);
	    do_chpass(session);
	    return;
	}
    }

    pw_ix = PW_LOGIN;
    set_pwdat(session, &pwdat, &pw_ix);

    if (query_mavis_auth_login(session, do_ascii_login, pw_ix))
	return;

    set_pwdat(session, &pwdat, &pw_ix);

    if (session->user && session->password && session->password_bad && !strcmp(session->password, session->password_bad)) {
	/* Safeguard against router-initiated login retries. Stops
	 * backend from prematurely locking the user's account,
	 * eventually.
	 */
	res = S_deny;
	hint = hint_failed_password_retry;
	session->password_bad_again = 1;
    } else {
	res = check_access(session, pwdat, session->password, &hint, &resp);
	session->password_bad_again = 0;
    }

    mem_free(session->mem, &session->challenge);

    report_auth(session, "shell login", hint, res);

    switch (res) {
    case S_error:
	send_authen_error(session, "Authentication backend failure.");
	return;
    case S_permit:
	if (session->passwd_mustchange) {
	    if (!session->user_msg.txt)
		session->user_msg.txt = eval_log_format(session, session->ctx, NULL, li_change_password, io_now.tv_sec, &session->user_msg.len);
	    session->flag_mavis_auth = 0;
	    session->authfn = do_chpass;
	    do_chpass(session);
	    return;
	}

	if (session->user->valid_until && session->user->valid_until < io_now.tv_sec + session->ctx->realm->warning_period)
	    session->user_msg.txt = eval_log_format(session, session->ctx, NULL, li_account_expires, io_now.tv_sec, &session->user_msg.len);

	send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_PASS, set_motd_banner(session), 0, NULL, 0, 0);
	return;
    default:
	;
    }

    if (++session->authen_data->iterations < session->ctx->host->authen_max_attempts) {
	m = eval_log_format(session, session->ctx, NULL,
			    (session->user && (session->user->chalresp == TRISTATE_YES)) ? li_response_incorrect_retry : li_password_incorrect_retry,
			    io_now.tv_sec, NULL);
	session->flag_mavis_auth = 0;
	send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_GETPASS, m, 0, NULL, 0, TAC_PLUS_REPLY_FLAG_NOECHO);
    } else {
	m = eval_log_format(session, session->ctx, NULL,
			    (session->user && (session->user->chalresp == TRISTATE_YES)) ? li_response_incorrect : li_password_incorrect,
			    io_now.tv_sec, NULL);
	send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_FAIL, m, 0, NULL, 0, 0);
    }
}

#ifdef WITH_CRYPTO
#define EAP_REQUEST     1
#define EAP_RESPONSE    2
#define EAP_SUCCESS     3
#define EAP_FAILURE     4
static int eap_step(tac_session *session __attribute__((unused)),
		    u_char *eap_in __attribute__((unused)), size_t eap_in_len __attribute__((unused)),
		    u_char *eap_out __attribute__((unused)), size_t *eap_out_len __attribute__((unused)))
{
    // This is a stub. An implementation bases on libeap (from hostapd) seems feasible,
    // but makes no sense without client support.
    *eap_out_len = 4;
    eap_out[0] = EAP_FAILURE;
    eap_out[1] = 0;
    eap_out[2] = 0;
    eap_out[3] = 4;
    return eap_out[0];
}

static void do_eap(tac_session *session)
{
    enum token res = S_deny;
    enum hint_enum hint = hint_nosuchuser;
    u_char eap_out[0x10000], *eap_in = NULL;
    size_t eap_out_len = 0, eap_in_len = 0;

    if (S_deny == lookup_and_set_user(session)) {
	report_auth(session, "shell login", hint_denied_by_acl, res);
	send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_FAIL, NULL, 0, NULL, 0, 0);
	return;
    }

    if (query_mavis_info_login(session, do_eap))
	return;

    if (!session->user) {
	send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_FAIL, eval_log_format(session, session->ctx, NULL, li_permission_denied, io_now.tv_sec, NULL), 0,
			  NULL, 0, 0);
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
	res = S_deny;
	break;
    case -1:			// delayed
	return;
    default:
	res = S_deny;
    }

    report_auth(session, "shell login", hint, res);

    if (res == S_permit) {
	if (session->user->valid_until && session->user->valid_until < io_now.tv_sec + session->ctx->realm->warning_period)
	    session->user_msg.txt = eval_log_format(session, session->ctx, NULL, li_account_expires, io_now.tv_sec, &session->user_msg.len);
	send_authen_reply(session, res, set_motd_banner(session), 0, eap_out, eap_out_len, 0);
    } else
	send_authen_reply(session, TAC_SYM_TO_CODE(res), NULL, 0, eap_out, eap_out_len, 0);
}
#endif

static void do_enable_getuser(tac_session *session)
{
    enum hint_enum hint = hint_nosuchuser;
    char *resp = eval_log_format(session, session->ctx, NULL, li_enable_password_incorrect, io_now.tv_sec, NULL);
    enum token res = S_deny;

    if (!session->username.txt[0] && session->authen_data->msg) {
	session->username.txt = session->authen_data->msg;
	session->username.len = session->authen_data->msg_len;
	session->authen_data->msg = NULL;
    }

    if (!session->username.txt[0]) {
	mem_free(session->mem, &session->username);
	send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_GETUSER,
			  eval_log_format(session, session->ctx, NULL, li_username, io_now.tv_sec, NULL), 0, NULL, 0, 0);
	return;
    }

    if (S_deny == lookup_and_set_user(session)) {
	report_auth(session, "enforced enable login", hint_denied_by_acl, S_deny);
	send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_FAIL, NULL, 0, NULL, 0, 0);
	return;
    }

    if (session->user && session->user->passwd[PW_LOGIN] && session->user->passwd[PW_LOGIN]->type == S_error) {
	send_authen_error(session, "Handling refused.");
	return;
    }

    if (query_mavis_info_login(session, do_enable_getuser))
	return;

    enum pw_ix pw_ix = PW_LOGIN;
    struct pwdat *pwdat = NULL;
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

    set_pwdat(session, &pwdat, &pw_ix);

    res = check_access(session, pwdat, session->password, &hint, &resp);
    mem_free(session->mem, &session->challenge);

    report_auth(session, "enforced enable login", hint, res);

    if (res == S_permit) {
	session->authfn = do_enable;
	do_enable(session);
    } else
	send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_FAIL, resp, 0, NULL, 0, 0);
}

#ifdef WITH_CRYPTO
static void mschap_desencrypt(u_char *in, u_char key[21], u_char out[8])
{
    unsigned char key_par[8];

    // make room for parity bits
    key_par[0] = key[0] & 0xfe;
    key_par[1] = ((key[0] << 7) | (key[1] >> 1)) & 0xfe;
    key_par[2] = ((key[1] << 6) | (key[2] >> 2)) & 0xfe;
    key_par[3] = ((key[2] << 5) | (key[3] >> 3)) & 0xfe;
    key_par[4] = ((key[3] << 4) | (key[4] >> 4)) & 0xfe;
    key_par[5] = ((key[4] << 3) | (key[5] >> 5)) & 0xfe;
    key_par[6] = ((key[5] << 2) | (key[6] >> 6)) & 0xfe;
    key_par[7] = (key[6] << 1) & 0xfe;

    // ensure odd parity
    for (int i = 0; i < 8; i++) {
	uint8_t r = key_par[i];
	uint8_t p = 1;
	while (r) {
	    if (r & 1)
		p ^= 1;
	    r >>= 1;
	}
	key_par[i] |= p;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_des_ecb(), NULL, key_par, NULL);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    int out_len = 8;
    EVP_EncryptUpdate(ctx, out, &out_len, in, 8);
    int tmp_len = 0;
    EVP_EncryptFinal_ex(ctx, out + out_len, &tmp_len);
    EVP_CIPHER_CTX_free(ctx);
}

static void mschap_chalresp(u_char chal[8], u_char nt_hash[16], u_char out[24])
{
    u_char hash_padded[21] = { 0 };

    memcpy(hash_padded, nt_hash, (size_t) 16);

    mschap_desencrypt(chal, hash_padded, out);
    mschap_desencrypt(chal, hash_padded + 7, out + 8);
    mschap_desencrypt(chal, hash_padded + 14, out + 16);
}

static void mschap_nthash(char *password, u_char *hash)
{
    char *buf = NULL;
    size_t buf_len = 0;
    size_t password_len = strlen(password);

    if (utf8_to_utf16le(password, password_len, &buf, &buf_len)) {
	// Not utf8, so just try copying
	buf = calloc(1, 2 * buf_len);
	for (char *b = buf; *password; b++)
	    *b++ = *password++;
    }

    myMD4_CTX context;
    MD4Init(&context);
    MD4Update(&context, (u_char *) buf, buf_len);
    MD4Final(hash, &context);
    free(buf);
}

static void mschapv1_ntresp(u_char chal[8], char *password, u_char resp[24])
{
    u_char nt_hash[16];

    mschap_nthash(password, nt_hash);
    mschap_chalresp(chal, nt_hash, resp);
}

static void do_mschap(tac_session *session)
{
    enum token res = S_deny;
    enum hint_enum hint = hint_nosuchuser;

    if (query_mavis_info(session, do_mschap, PW_MSCHAP))
	return;

    if (S_deny == lookup_and_set_user(session)) {
	report_auth(session, "mchap login", hint_denied_by_acl, res);
	send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_FAIL, NULL, 0, NULL, 0, 0);
	return;
    }

    if (query_mavis_info(session, do_mschap, PW_MSCHAP))
	return;

    if (session->user) {
	if (session->user->passwd[PW_MSCHAP]->type != S_clear) {
	    hint = hint_no_cleartext;
	    report_auth(session, "mschap login", hint, res);
	    send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_RESTART, NULL, 0, NULL, 0, 0);
	    return;
	}
	if (session->authen_data->data_len == 1 /* PPP id */  + 8 /* challenge length */  + MSCHAP_DIGEST_LEN) {
	    u_char response[24];
	    u_char *chal = session->authen_data->data + 1;
	    u_char *resp = session->authen_data->data + session->authen_data->data_len - MSCHAP_DIGEST_LEN;
	    session->authen_data->data = NULL;

	    if (resp[48]) {
		mschapv1_ntresp(chal, session->user->passwd[PW_MSCHAP]->value, response);
		if (!memcmp(response, resp + 24, 24))
		    res = S_permit;
	    }

	    if (res == S_permit)
		res = user_invalid(session->user, &hint);
	    if (res == S_permit) {
		char *tmp = NULL;
		session->mavisauth_res = S_permit;
		res = check_access(session, NULL, session->user->passwd[PW_MSCHAP]->value, &hint, &tmp);
	    } else {
		hint = hint_failed;
		res = S_deny;
	    }
	} else
	    hint = hint_invalid_challenge_length;
    }

    report_auth(session, "mschap login", hint, res);

    send_authen_reply(session, TAC_SYM_TO_CODE(res), NULL, 0, NULL, 0, 0);
}

static void mschapv2_chal(u_char peer_challenge[16], u_char auth_challenge[16], char *username, u_char out[8])
{
    uint8_t digest[SHA_DIGEST_LENGTH];
#if OPENSSL_VERSION_NUMBER < 0x30000000
    SHA_CTX ctx;
    SHA1_Init(&ctx);
    SHA1_Update(&ctx, peer_challenge, 16);
    SHA1_Update(&ctx, auth_challenge, 16);
    SHA1_Update(&ctx, username, strlen(username));
    SHA1_Final(digest, &ctx);
#else
    unsigned int digest_len = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha1(), NULL);
    EVP_DigestUpdate(ctx, peer_challenge, 16);
    EVP_DigestUpdate(ctx, auth_challenge, 16);
    EVP_DigestUpdate(ctx, username, strlen(username));
    EVP_DigestFinal_ex(ctx, digest, &digest_len);
    EVP_MD_CTX_free(ctx);
#endif
    memcpy(out, digest, 8);
}

static void mschapv2_ntresp(u_char peer_challenge[16], u_char auth_challenge[16], char *username, char *password, u_char response[24])
{
    u_char chal[8];
    mschapv2_chal(peer_challenge, auth_challenge, username, chal);

    uint8_t nt_hash[16];

    mschap_nthash(password, nt_hash);
    mschap_chalresp(chal, nt_hash, response);
}

static void do_mschapv2(tac_session *session)
{
    enum token res = S_deny;
    enum hint_enum hint = hint_nosuchuser;

    if (S_deny == lookup_and_set_user(session)) {
	report_auth(session, "mchapv2 login", hint_denied_by_acl, res);
	send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_FAIL, NULL, 0, NULL, 0, 0);
	return;
    }
    if (query_mavis_info(session, do_mschapv2, PW_MSCHAP))
	return;

    if (session->user) {
	if (session->user->passwd[PW_MSCHAP]->type != S_clear) {
	    hint = hint_no_cleartext;
	    report_auth(session, "mschapv2 login", hint, res);
	    send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_RESTART, NULL, 0, NULL, 0, 0);
	    return;
	}
	if (session->authen_data->data_len == 1 /* PPP id */  + 16 /* challenge length */  + MSCHAP_DIGEST_LEN) {
	    u_char *chal = session->authen_data->data + 1;
	    u_char *resp = session->authen_data->data + session->authen_data->data_len - MSCHAP_DIGEST_LEN;
	    session->authen_data->data = NULL;
	    u_char reserved = 0;
	    for (u_char * r = resp + 16; r < resp + 24; r++)
		reserved |= *r;
	    if (!reserved && !resp[48] /* reserved, must be zero */ ) {
		u_char response[24];

		mschapv2_ntresp(resp /* == peer chal */ , chal, session->user->name.txt, session->user->passwd[PW_MSCHAP]->value, response);
		if (!memcmp(response, resp + 24, 24))
		    res = S_permit;
	    }

	    if (res == S_permit)
		res = user_invalid(session->user, &hint);
	    if (res == S_permit) {
		char *tmp = NULL;
		session->mavisauth_res = S_permit;
		res = check_access(session, NULL, session->user->passwd[PW_MSCHAP]->value, &hint, &tmp);
	    } else {
		hint = hint_failed;
		res = S_deny;
	    }
	} else
	    hint = hint_invalid_challenge_length;
    }

    report_auth(session, "mschapv2 login", hint, res);

    send_authen_reply(session, TAC_SYM_TO_CODE(res), NULL, 0, NULL, 0, 0);
}
#endif

static void do_login(tac_session *session)
{
    enum token res = S_deny;
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
	send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_FAIL, NULL, 0, NULL, 0, 0);
	return;
    }
    if (query_mavis_info_login(session, do_login))
	return;

    enum pw_ix pw_ix = PW_LOGIN;
    struct pwdat *pwdat = NULL;
    set_pwdat(session, &pwdat, &pw_ix);

    if (query_mavis_auth_login(session, do_login, pw_ix))
	return;

    set_pwdat(session, &pwdat, &pw_ix);

    res = check_access(session, pwdat, session->password, &hint, &resp);

    report_auth(session, "ascii login", hint, res);

    send_authen_reply(session, TAC_SYM_TO_CODE(res), resp, 0, NULL, 0, 0);
}

static void do_pap(tac_session *session)
{
    enum token res = S_deny;
    enum hint_enum hint = hint_nosuchuser;
    char *resp = NULL;

    if (session->ctx->host->map_pap_to_login == TRISTATE_YES) {
	do_login(session);
	return;
    }

    mem_free(session->mem, &session->password);

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
	send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_FAIL, NULL, 0, NULL, 0, 0);
	return;
    }
    if (query_mavis_info_pap(session, do_pap))
	return;

    enum pw_ix pw_ix = PW_PAP;
    struct pwdat *pwdat = NULL;
    set_pwdat(session, &pwdat, &pw_ix);

    if (query_mavis_auth_pap(session, do_pap, pw_ix))
	return;

    res = check_access(session, pwdat, session->password, &hint, &resp);

    report_auth(session, "pap login", hint, res);

    if (!resp)
	resp = session->user_msg.txt;

    send_authen_reply(session, TAC_SYM_TO_CODE(res), resp, 0, NULL, 0, 0);
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
static void do_sshkeyhash(tac_session *session)
{
    enum token res = S_deny;
    enum hint_enum hint = hint_nosuchuser;
    char *resp = NULL;
    char *key = NULL;

    if (S_deny == lookup_and_set_user(session)) {
	report_auth(session, "ssh-key-hash login", hint_denied_by_acl, res);
	send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_FAIL, NULL, 0, NULL, 0, 0);
	return;
    }
    if (query_mavis_info(session, do_sshkeyhash, PW_LOGIN))
	return;

    session->ssh_key_hash = (char *) session->authen_data->data;

    if (session->user && session->ssh_key_hash && *session->ssh_key_hash) {
	res = validate_ssh_hash(session, session->ssh_key_hash, &key);

	if (res == S_permit) {
	    res = session->authorized ? S_permit : ((S_deny == author_eval_host(session, session->ctx->host, session->ctx->realm->script_host_parent_first)
						     || S_permit != eval_ruleset(session, session->ctx->realm)) ? S_deny : S_permit);

	    if (res == S_permit)
		hint = hint_permitted;
	    else {
		hint = hint_denied_by_acl;
	    }
	} else
	    hint = hint_denied;

	if (res == S_permit) {
	    mem_free(session->mem, &session->password);
	    if (res != S_permit && session->ctx->host->reject_banner)
		resp = eval_log_format(session, session->ctx, NULL, session->ctx->host->reject_banner, io_now.tv_sec, NULL);
	    if (res == S_permit)
		res = user_invalid(session->user, &hint);
	}
    }

    if (res == S_permit)
	hint = hint_permitted;
    report_auth(session, "ssh-key-hash login", hint, res);

    send_authen_reply(session, TAC_SYM_TO_CODE(res), resp, 0, (u_char *) key, 0, 0);
}

// This is proof-of-concept code for SSH certificate validation with minor protocol changes.
// Clients just need to use TAC_PLUS_AUTHEN_TYPE_SSHCERTASH (9) and put the client certificate
// key-id into the data field. The daemon will return a matching AuthorizedPrincipalsFile line. 
//
// OpenSSH integration is easily possible, too, via AuthorizedPrincipalsCommand.
//

static void do_sshcerthash(tac_session *session)
{
    enum token res = S_deny;
    enum hint_enum hint = hint_nosuchuser;
    char *resp = NULL;
    char *key = NULL;

    if (S_deny == lookup_and_set_user(session)) {
	report_auth(session, "ssh-cert-hash login", hint_denied_by_acl, res);
	send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_FAIL, NULL, 0, NULL, 0, 0);
	return;
    }
    if (query_mavis_info(session, do_sshcerthash, PW_LOGIN))
	return;

    session->ssh_key_id = (char *) session->authen_data->data;

    if (session->user && session->ssh_key_id && *session->ssh_key_id) {
	res = validate_ssh_key_id(session);
	if (res == S_permit) {
	    res = session->authorized ? S_permit : ((S_deny == author_eval_host(session, session->ctx->host, session->ctx->realm->script_host_parent_first)
						     || S_permit != eval_ruleset(session, session->ctx->realm)) ? S_deny : S_permit);

	    hint = (res == S_permit) ? hint_permitted : hint_denied_by_acl;
	} else
	    hint = hint_denied;

	if (res == S_permit) {
	    mem_free(session->mem, &session->password);
	    if (res != S_permit && session->ctx->host->reject_banner)
		resp = eval_log_format(session, session->ctx, NULL, session->ctx->host->reject_banner, io_now.tv_sec, NULL);
	    if (res == S_permit)
		res = user_invalid(session->user, &hint);
	}
    }

    if (res == S_permit)
	hint = hint_permitted;
    report_auth(session, "ssh-key-hash login", hint, res);

    send_authen_reply(session, TAC_SYM_TO_CODE(res), resp, 0, (u_char *) key, 0, 0);
}

void free_reverse(void *payload, void *data __attribute__((unused)))
{
    if (payload) {
	if (((struct revmap *) payload)->name)
	    free(((struct revmap *) payload)->name);
	free(payload);
    }
}

void add_revmap(tac_realm *r, struct in6_addr *address, char *hostname, int ttl, int table)
{
    while (r && !r->idc)
	r = r->parent;
    if (r) {
	struct revmap *rev;
	if (!hostname)
	    hostname = "";
	if (!r->dns_tree_ptr[table])
	    r->dns_tree_ptr[table] = radix_new(free_reverse, NULL);
	rev = radix_lookup(r->dns_tree_ptr[table], address, NULL);
	if (rev) {
	    if (rev->name)
		free(rev->name);
	} else {
	    rev = calloc(1, sizeof(struct revmap));
	    radix_add(r->dns_tree_ptr[table], address, 128, rev);
	}
	rev->name = strdup(hostname);
	rev->ttl = (ttl == -1) ? -1 : io_now.tv_sec + ttl;
    }
}

#ifdef WITH_DNS
static void set_revmap_nac(tac_session *session, char *hostname, int ttl)
{
    report(session, LOG_DEBUG, DEBUG_DNS_FLAG, "NAC revmap(%s) = %s", session->nac_addr_ascii.txt, hostname ? hostname : "(not found)");
    if (hostname)
	str_set(&session->nac_dns_name, mem_strdup(session->mem, hostname), 0);

    session->revmap_pending = 0;
    session->revmap_timedout = 0;

    add_revmap(session->ctx->realm, &session->nac_address, hostname, ttl, 1);

    if (!session->ctx->revmap_pending && session->resumefn)
	resume_session(session, -1);
}
#endif

void get_revmap_nac(tac_session *session)
{
    tac_realm *r = session->ctx->realm;
    if (session->nac_addr_valid) {
	while (r) {
	    for (int i = 0; i < 3; i++) {
		if (r->dns_tree_ptr[i]) {
		    struct revmap *rev = radix_lookup(r->dns_tree_ptr[i], &session->nac_address, NULL);
		    if (rev && rev->name && rev->ttl >= io_now.tv_sec) {
			str_set(&session->nac_dns_name, mem_strdup(session->mem, rev->name), 0);
			report(NULL, LOG_DEBUG, DEBUG_DNS_FLAG, "NAC revmap(%s) = %s [TTL: %lld]", session->nac_addr_ascii.txt, rev->name,
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
	    report(session, LOG_DEBUG, DEBUG_DNS_FLAG, "Querying NAC revmap (%s)", session->nac_addr_ascii.txt);
	    io_dns_add_addr(r->idc, &session->nac_address, (void *) set_revmap_nac, session);
	}
    }
#endif
}

#ifdef WITH_DNS
static void set_revmap_nas(struct context *ctx, char *hostname, int ttl)
{
    if (!hostname)
	ttl = 60;

    report(NULL, LOG_DEBUG, DEBUG_DNS_FLAG, "NAS revmap(%s) = %s [TTL: %d]", ctx->device_addr_ascii.txt, hostname ? hostname : "(not found)", ttl);

    if (hostname)
	str_set(&ctx->device_dns_name, mem_strdup(ctx->mem, hostname), 0);

    ctx->revmap_pending = 0;
    ctx->revmap_timedout = 0;

    add_revmap(ctx->realm, &ctx->device_addr, hostname, ttl, 1);

    for (rb_node_t * rbnext, *rbn = RB_first(ctx->sessions); rbn; rbn = rbnext) {
	tac_session *session = RB_payload(rbn, tac_session *);
	rbnext = RB_next(rbn);

	if (!session->revmap_pending && session->resumefn)
	    resume_session(session, -1);
    }
}
#endif


void get_revmap_nas(tac_session *session)
{
    struct context *ctx = session->ctx;
    if (!ctx->device_dns_name.txt) {
	tac_realm *r = ctx->realm;
	while (r) {
	    for (int i = 0; i < 3; i++) {
		if (r->dns_tree_ptr[i]) {
		    struct revmap *rev = radix_lookup(r->dns_tree_ptr[i], &ctx->device_addr, NULL);
		    if (rev && rev->name && rev->ttl >= io_now.tv_sec) {
			str_set(&ctx->device_dns_name, mem_strdup(ctx->mem, rev->name), 0);
			report(NULL, LOG_DEBUG, DEBUG_DNS_FLAG, "NAS revmap(%s) = %s [TTL: %lld]", ctx->device_addr_ascii.txt, rev->name,
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
	    if (r) {
		ctx->revmap_pending = 1;
		report(session, LOG_DEBUG, DEBUG_DNS_FLAG, "Querying NAS revmap (%s)", ctx->device_addr_ascii.txt);
		io_dns_add_addr(r->idc, &ctx->device_addr, (void *) set_revmap_nas, ctx);
	    }
	}
#endif
    }
}

#ifdef WITH_DNS
void resume_session(tac_session *session, int cur __attribute__((unused)))
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
#endif

void authen_init(void)
{
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
    li_password_changed = parse_log_format_inline("\"${PASSWORD_CHANGED}\"", __FILE__, __LINE__);
    li_change_password = parse_log_format_inline("\"${CHANGE_PASSWORD}\n\"", __FILE__, __LINE__);
    li_enable_password_incorrect = parse_log_format_inline("\"${PASSWORD_INCORRECT}\n\"", __FILE__, __LINE__);
    li_password_incorrect = parse_log_format_inline("\"${PASSWORD_INCORRECT}\n${AUTHFAIL_BANNER}\"", __FILE__, __LINE__);
    li_password_incorrect_retry = parse_log_format_inline("\"${PASSWORD_INCORRECT}\n${PASSWORD}\"", __FILE__, __LINE__);
    li_response_incorrect_retry = parse_log_format_inline("\"${RESPONSE_INCORRECT}\n${RESPONSE}\"", __FILE__, __LINE__);
    li_account_expires = parse_log_format_inline("\"${ACCOUNT_EXPIRES}\n\"", __FILE__, __LINE__);
    li_password_expired = parse_log_format_inline("\"${PASSWORD_EXPIRED}\n\"", __FILE__, __LINE__);
    li_password_expires = parse_log_format_inline("\"${PASSWORD_EXPIRES}\n\"", __FILE__, __LINE__);
    li_denied_by_acl = parse_log_format_inline("\"${DENIED_BY_ACL}\"", __FILE__, __LINE__);
#if OPENSSL_VERSION_NUMBER >= 0x30000000
    ossl_legacy = OSSL_PROVIDER_load(NULL, "legacy");
    ossl_default = OSSL_PROVIDER_load(NULL, "default");
#endif
}

char *check_client_bug_invalid_remote_address(tac_session *session)
{
    char *res = session->nac_addr_ascii.txt;
    if (session->ctx->host->bug_compatibility & CLIENT_BUG_INVALID_REMOTE_ADDRESS) {
	char *t = strchr(res, ' ');
	if (t) {
	    *t = 0;
	    res = mem_strdup(session->mem, res);
	    *t = ' ';
	}
    }
    return res;
}

void authen(tac_session *session, tac_pak_hdr *hdr)
{
    int username_required = 1;
    struct authen_start *start = tac_payload(hdr, struct authen_start *);
    struct authen_cont *cont = tac_payload(hdr, struct authen_cont *);

    report(DEBAUTHC, "%s: hdr->seq_no: %d", __func__, hdr->seq_no);

    if (!session->authen_data)
	session->authen_data = mem_alloc(session->mem, sizeof(struct authen_data));

    if (hdr->seq_no == 1) {
	get_pkt_data(session, start, NULL);

	switch (start->action) {
	case TAC_PLUS_AUTHEN_LOGIN:
	    switch (start->service) {
	    case TAC_PLUS_AUTHEN_SVC_ENABLE:
		session->authfn = do_enable;
		username_required = 0;
		break;
	    default:
		switch (start->type) {
		case TAC_PLUS_AUTHEN_TYPE_ASCII:
		    if (((session->ctx->host->bug_compatibility & CLIENT_BUG_INVALID_START_DATA) || (common_data.debug & DEBUG_TACTRACE_FLAG))
			&& start->user_len && start->data_len) {
			/* PAP-like inbound login. Not in rfc8907, but used by IOS-XR. */
			session->authfn = do_login;
		    } else {
			/* Standard ASCII login */
			session->authfn = do_ascii_login;
			session->passwd_changeable = 1;
			username_required = 0;
			start->data_len = 0;	/* rfc8907 5.4.2.1 says to ignore the data field */
		    }
		    break;
		case TAC_PLUS_AUTHEN_TYPE_PAP:
		    session->authfn = do_pap;
		    break;
		case TAC_PLUS_AUTHEN_TYPE_CHAP:
		    if (hdr->version == TAC_PLUS_VER_ONE)
			session->authfn = do_chap;
		    break;
#ifdef WITH_CRYPTO
		case TAC_PLUS_AUTHEN_TYPE_MSCHAP:
		    if (hdr->version == TAC_PLUS_VER_ONE)
			session->authfn = do_mschap;
		    break;
		case TAC_PLUS_AUTHEN_TYPE_MSCHAPV2:
		    if (hdr->version == TAC_PLUS_VER_ONE)
			session->authfn = do_mschapv2;
		    break;
#endif
		case TAC_PLUS_AUTHEN_TYPE_SSHKEY:
		    // limit to hdr->version? 1.2 perhaps?
		    session->authfn = do_sshkeyhash;
		    break;
		case TAC_PLUS_AUTHEN_TYPE_SSHCERT:
		    // limit to hdr->version? 1.2 perhaps?
		    session->authfn = do_sshcerthash;
		    break;
#ifdef WITH_CRYPTO
		case TAC_PLUS_AUTHEN_TYPE_EAP:
		    // limit to hdr->version? 1.2 perhaps?
		    session->authfn = do_eap;
		    break;
#endif
		}
	    }
	    break;
	case TAC_PLUS_AUTHEN_CHPASS:
	    if (session->ctx->realm->chpass == TRISTATE_YES)
		switch (start->type) {
		case TAC_PLUS_AUTHEN_TYPE_ASCII:
		    session->authfn = do_chpass;
		    session->chpass = 1;
		    session->passwd_changeable = 1;
		    username_required = 0;
		    break;
		}
	    break;
	}

	if (session->authfn) {
	    u_char *p = (u_char *) start + TAC_AUTHEN_START_FIXED_FIELDS_SIZE;
	    str_set(&session->username, mem_strndup(session->mem, p, start->user_len), start->user_len);
	    tac_user *u = lookup_user(session);

	    if (u && u->passwd[PW_LOGIN] && u->passwd[PW_LOGIN]->type == S_error) {
		send_authen_error(session, "Handling refused.");
		return;
	    }

	    p += start->user_len;
	    str_set(&session->port, mem_strndup(session->mem, p, start->port_len), start->port_len);
	    p += start->port_len;
	    str_set(&session->nac_addr_ascii, mem_strndup(session->mem, p, start->rem_addr_len), start->rem_addr_len);
	    char *nac_addr_ascii = check_client_bug_invalid_remote_address(session);
	    session->nac_addr_valid = v6_ptoh(&session->nac_address, NULL, nac_addr_ascii) ? 0 : 1;
	    if (session->nac_addr_valid)
		get_revmap_nac(session);
	    p += start->rem_addr_len;
	    session->authen_data->data = (u_char *) mem_copy(session->mem, p, start->data_len);
	    session->authen_data->data_len = start->data_len;

	    session->priv_lvl = start->priv_lvl;
	    if (session->priv_lvl & ~0xf) {
		send_authen_error(session, "Invalid privilege level %d in packet.", session->priv_lvl);
		return;
	    }
	}
    } else if (cont->flags & TAC_PLUS_CONTINUE_FLAG_ABORT) {
	char *t = hints[hint_abort].plain.txt;
	size_t l = ntohs(cont->user_data_len) + 100;
	char *tmp = alloca(l);
	if (cont->user_data_len) {
	    snprintf(tmp, l, "%s (%*s)", t, cont->user_msg_len, (char *) cont + TAC_AUTHEN_CONT_FIXED_FIELDS_SIZE + ntohs(cont->user_msg_len));
	    t = tmp;
	}
	report_auth(session, t, hint_abort, S_deny);
	cleanup_session(session);
	return;
    } else {			/* hdr->seq_no != 1 */
	username_required = 0;
	session->authen_data->msg_len = ntohs(cont->user_msg_len);
	session->authen_data->data_len = ntohs(cont->user_data_len);
#ifdef WITH_CRYPTO
	if (session->authfn == do_eap) {
	    // no need to duplicate, do_eap() doesn't need a local null-terminated copy right now.
	    session->authen_data->msg = (char *) cont + TAC_AUTHEN_CONT_FIXED_FIELDS_SIZE;
	    session->authen_data->data = (u_char *) cont + TAC_AUTHEN_CONT_FIXED_FIELDS_SIZE + session->authen_data->msg_len;
	} else
#endif
	{
	    session->authen_data->msg = mem_copy(session->mem, (u_char *) cont + TAC_AUTHEN_CONT_FIXED_FIELDS_SIZE, session->authen_data->msg_len);
	    session->authen_data->data =
		(u_char *) mem_copy(session->mem, (u_char *) cont + TAC_AUTHEN_CONT_FIXED_FIELDS_SIZE + session->authen_data->msg_len,
				    session->authen_data->data_len);
	}
    }

    if (session->authfn) {
	if (username_required && !session->username.txt[0])
	    send_authen_error(session, "No username in packet");
	else {
#ifdef WITH_DNS
	    if ((hdr->seq_no == 1) && (session->ctx->host->dns_timeout > 0) && (session->revmap_pending || session->ctx->revmap_pending)) {
		session->resumefn = session->authfn;
		io_sched_add(session->ctx->io, session, (void *) resume_session, session->ctx->host->dns_timeout, 0);
	    } else
#endif
		session->authfn(session);
	}
    } else
	send_authen_error(session, "Invalid or unsupported AUTHEN/START (action=%d authen_type=%d)", start->action, start->type);
}

static void do_radius_login(tac_session *session)
{
    enum token res = S_deny;
    enum hint_enum hint = hint_nosuchuser;
    char *info = "radius login";
#define rd session->radius_data

    if (!session->username.txt) {
	report_auth(session, info, hint_denied, res);
	rad_send_authen_reply(session, RADIUS_CODE_ACCESS_REJECT, NULL);
	return;
    }
    if (rd->type == S_unknown) {
	int pw_res = (session->ctx->radius_1_1 ? rad_get(rd->pak_in, session->mem, -1, RADIUS_A_USER_PASSWORD, S_string_keyword, &session->password,
							 NULL) : rad_get_password(session, &session->password, NULL));
	if (pw_res < 0)
	    hint = hint_nopass;
	else if (pw_res > 0)
	    hint = hint_badsecret;
	else {
	    rd->type = S_pap;
	    rd->pw_ix = PW_LOGIN;
	}
    }

    if (rd->type == S_unknown) {
	if (!rad_get(rd->pak_in, session->mem, -1, RADIUS_A_CHAP_PASSWORD, S_octets, &rd->chap_password, &rd->chap_password_len)
	    && rd->chap_password_len == 1 + MD5_LEN) {
	    if (rad_get(rd->pak_in, session->mem, -1, RADIUS_A_CHAP_CHALLENGE, S_octets, &rd->chap_challenge, &rd->chap_challenge_len)) {
		if (session->ctx->radius_1_1 == BISTATE_NO) {
		    rd->chap_challenge = rd->pak_in->authenticator;
		    rd->chap_challenge_len = 16;
		}
	    }
	    if (rd->chap_challenge_len) {
		rd->type = S_chap;
		rd->pw_ix = PW_CHAP;
	    }
	}
    }

#ifdef WITH_CRYPTO
#define mschap_challenge chap_challenge
#define mschap_challenge_len chap_challenge_len
#define mschap_response chap_password
#define mschap_response_len chap_password_len

    if (rd->type == S_unknown) {
	if (!rad_get(rd->pak_in, session->mem, RADIUS_VID_MICROSOFT, RADIUS_A_MS_CHAP_CHALLENGE, S_octets, &rd->mschap_challenge, &rd->mschap_challenge_len)
	    && (rd->mschap_challenge_len > 0)
	    && !rad_get(rd->pak_in, session->mem, RADIUS_VID_MICROSOFT, RADIUS_A_MS_CHAP_RESPONSE, S_octets, &rd->mschap_response,
			&rd->mschap_response_len) && (rd->mschap_response_len == 50)) {
	    rd->type = S_mschap;
	    rd->pw_ix = PW_MSCHAP;
	    rd->mschap_version = 1;
	}
    }

    if (rd->type == S_unknown) {
	if (!rad_get(rd->pak_in, session->mem, RADIUS_VID_MICROSOFT, RADIUS_A_MS_CHAP_CHALLENGE, S_octets, &rd->mschap_challenge, &rd->mschap_challenge_len)
	    && (rd->mschap_challenge_len > 0)
	    && !rad_get(rd->pak_in, session->mem, RADIUS_VID_MICROSOFT, RADIUS_A_MS_CHAP2_RESPONSE, S_octets, &rd->mschap_response,
			&rd->mschap_response_len) && (rd->mschap_response_len == 50)) {
	    rd->type = S_mschap;
	    rd->pw_ix = PW_MSCHAP;
	    rd->mschap_version = 2;
	    u_char *chal = mem_alloc(session->mem, 8);
	    mschapv2_chal(rd->mschap_response + 2, rd->mschap_challenge, session->username.txt, chal);
	    rd->mschap_challenge = chal;
	    rd->mschap_challenge_len = 8;
	}
    }
#endif

    if (rd->type == S_unknown) {
	report_auth(session, info, hint, res);
	rad_send_authen_reply(session, RADIUS_CODE_ACCESS_REJECT, NULL);
	return;
    }

    if (rd->type == S_pap && password_requirements_failed(session, info))
	return;

    if (S_deny == lookup_and_set_user(session)) {
	report_auth(session, info, hint_denied_by_acl, res);
	rad_send_authen_reply(session, RADIUS_CODE_ACCESS_REJECT, NULL);
	return;
    }

    char *resp = NULL;

    if (rd->type != S_pap && query_mavis_info_login(session, do_radius_login))
	return;
    if (session->user && session->user->passwd[rd->pw_ix] && session->user->passwd[rd->pw_ix]->type == S_error) {
	cleanup_session(session);
	return;
    }
    if (session->user || rd->type == S_pap) {
	if (rd->type == S_pap) {
	    if (query_mavis_info(session, do_radius_login, rd->pw_ix))
		return;
	    struct pwdat *pwdat = NULL;
	    set_pwdat(session, &pwdat, &rd->pw_ix);
	    if (query_mavis_auth_login(session, do_radius_login, rd->pw_ix))
		return;
	    if (session->user) {
		res = check_access(session, pwdat, session->password, &hint, &resp);
		info = "radius pap login";
	    }
	} else if (rd->type == S_chap) {
	    if (session->user->passwd[PW_CHAP] && session->user->passwd[PW_CHAP]->type == S_clear) {
		struct pwdat *pwdat = NULL;
		set_pwdat(session, &pwdat, &rd->pw_ix);
		struct iovec iov[3] = {
		    {.iov_base = rd->chap_password,.iov_len = 1 },
		    {.iov_base = session->user->passwd[PW_CHAP]->value,.iov_len = strlen(session->user->passwd[PW_CHAP]->value) },
		    {.iov_base = rd->chap_challenge,.iov_len = rd->chap_challenge_len },
		};
		u_char digest[MD5_LEN];
		md5v(digest, MD5_LEN, iov, 3);
		if (memcmp(rd->chap_password + 1, digest, MD5_LEN)) {
		    hint = hint_failed;
		    res = S_deny;
		} else {
		    session->mavisauth_res = S_permit;
		    res = check_access(session, NULL, session->user->passwd[PW_CHAP]->value, &hint, &resp);
		}
	    } else {
		hint = hint_no_cleartext;
		res = S_deny;
	    }
	    info = "radius chap login";
	}
#ifdef WITH_CRYPTO
	else if (rd->type == S_mschap) {
	    if (session->user->passwd[PW_MSCHAP] && session->user->passwd[PW_MSCHAP]->type == S_clear) {
		struct pwdat *pwdat = NULL;
		set_pwdat(session, &pwdat, &rd->pw_ix);
		if ((rd->mschap_version == 1 && rd->mschap_response[1] == 0x01) || (rd->mschap_version == 2)) {
		    u_char response[24];
		    mschapv1_ntresp(rd->mschap_challenge, session->user->passwd[PW_MSCHAP]->value, response);
		    u_char *peer_response = rd->mschap_response + 2 + 24;
		    if (!memcmp(response, peer_response, 24))
			res = S_permit;
		}
		if (res == S_permit) {
		    session->mavisauth_res = S_permit;
		    res = check_access(session, NULL, session->user->passwd[PW_MSCHAP]->value, &hint, &resp);
		} else {
		    hint = hint_failed;
		    res = S_deny;
		}
	    } else {
		hint = hint_no_cleartext;
		res = S_deny;
	    }
	    info = rd->mschap_version == 1 ? "radius mschap login" : "radius mschapv2 login";
	}
    }
#endif

    if (res == S_error) {
	// Backend failure.
	report_auth(session, info, hint, res);
	rad_send_error(session, RADIUS_V_ERROR_CAUSE_RESOURCES_UNAVAILABLE);
	return;
    }

    if (res == S_permit && session->profile) {
	session->debug |= session->profile->debug;
	res = author_eval_profile(session, session->profile, session->ctx->realm->script_profile_parent_first);

	if (res != S_permit) {
	    report(session, LOG_DEBUG, DEBUG_AUTHOR_FLAG, "user %s realm %s denied by ACL", session->username.txt, session->ctx->realm->name.txt);
	    res = S_deny;
	    resp = eval_log_format(session, session->ctx, NULL, li_denied_by_acl, io_now.tv_sec, NULL);
	}
    }

    report_auth(session, info, hint, res);

    if (!resp)
	resp = session->user_msg.txt;

    rad_send_authen_reply(session, RAD_SYM_TO_CODE(res), resp);
}

static void do_radius_dacl(tac_session *session)
{
    int first = 0;
    enum token res = S_deny;
    if (!rd->dacl) {
	first = 1;
	if (!session->username.txt)
	    goto fail;
	char *u = session->username.txt;
	if (!strncmp(u, ACSACL, sizeof(ACSACL) - 1))
	    u += sizeof(ACSACL) - 1;
	char *h = strrchr(u, '-');
	if (h)
	    *h = 0;
	str_set(&session->username, u, h - u);
	if (query_mavis_dacl(session, do_radius_dacl))
	    return;
	rd->dacl = lookup_dacl(u, session->ctx->realm);
	if (!rd->dacl)
	    goto fail;
    }

    void *val = NULL;
    size_t val_len = 0;
    uint32_t nace = 0;
    if (!rad_get(rd->pak_in, session->mem, -1, RADIUS_A_STATE, S_octets, &val, &val_len)) {
	if (!val || val_len != sizeof(uint32_t))
	    goto fail;
	memcpy(&nace, val, sizeof(uint32_t));
	nace = ntohl(nace);
    }

    if (rad_attr_add_dacl(session, rd->dacl, &nace))
	rad_send_authen_reply(session, RADIUS_CODE_ACCESS_REJECT, NULL);
    else if (nace == rd->dacl->nace)
	rad_send_authen_reply(session, RADIUS_CODE_ACCESS_ACCEPT, NULL);
    else {
	if (first)
	    dacl_copy(session);
	rad_send_authen_reply(session, RADIUS_CODE_ACCESS_CHALLENGE, NULL);
    }
    return;

  fail:
    report_auth(session, "dacl request", hint_failed, res);
    rad_send_authen_reply(session, RADIUS_CODE_ACCESS_REJECT, NULL);
}

void rad_authen(tac_session *session)
{
    if (rd->pak_in->code == RADIUS_CODE_ACCESS_REQUEST) {
	if (rad_check_dacl(session)) {
	    do_radius_dacl(session);
	    return;
	}
	session->authfn = do_radius_login;
	if (session->nac_addr_valid)
	    get_revmap_nac(session);
#ifdef WITH_DNS
	if ((session->ctx->host->dns_timeout > 0) && (session->revmap_pending || session->ctx->revmap_pending)) {
	    session->resumefn = session->authfn;
	    io_sched_add(session->ctx->io, session, (void *) resume_session, session->ctx->host->dns_timeout, 0);
	    return;
	}
#endif
	session->authfn(session);
	return;
    }
    cleanup_session(session);
}

#undef rd

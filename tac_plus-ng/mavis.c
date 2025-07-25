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
    struct timeval start;
};

struct mavis_ctx_data {
    const char *mavistype;
    void (*mavisfn)(struct context *);
    struct timeval start;
};

static void mavis_lookup_final(tac_session *, av_ctx *);

static void mavis_switch(tac_session *session, av_ctx *avc, int result)
{
    if (!session->user_is_session_specific)
	session->user = NULL;	/* may be outdated */

    switch (result) {
    case MAVIS_FINAL:
	session->mavis_pending = 0;
	mavis_lookup_final(session, avc);
	if (!session->user_msg.txt) {
	    char *comment = av_get(avc, AV_A_USER_RESPONSE);
	    if (comment) {
		size_t len = strlen(comment);
		session->user_msg.txt = mem_alloc(session->mem, len + 2);
		memcpy(session->user_msg.txt, comment, len);
		if (len && session->user_msg.txt[len - 1] != '\n')
		    session->user_msg.txt[len++] = '\n';
		session->user_msg.len = len;
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
	report(session, LOG_INFO_MAVIS, ~0, "auth_mavis: giving up (%s)", session->username.txt);
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

static void mavis_callback(tac_session *session)
{
    av_ctx *avc = NULL;
    int rc = mavis_recv(lookup_mcx(session->ctx->realm), &avc, session);
    mavis_switch(session, avc, rc);
}

void mavis_lookup(tac_session *session, void (*f)(tac_session *), const char *const type, enum pw_ix pw_ix)
{
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
	    report(session, LOG_ERR, ~0, "username '%s' looks bogus", session->username.txt);
	    f(session);
	    return;
	}
    }

    if ((r->mavis_userdb != TRISTATE_YES) && !session->user) {
	f(session);
	return;
    }

    report(session, LOG_INFO_MAVIS, ~0, "looking for user %s in MAVIS backend", session->username.txt);

    if (!session->mavis_data)
	session->mavis_data = mem_alloc(session->mem, sizeof(struct mavis_data));

    session->mavis_data->mavisfn = f;
    session->mavis_data->mavistype = type;
    session->mavis_data->pw_ix = pw_ix;
    session->mavis_data->start = io_now;

    av_ctx *avc = av_new((void *) mavis_callback, (void *) session);
    av_set(avc, AV_A_TYPE, AV_V_TYPE_TACPLUS);
    av_set(avc, AV_A_USER, session->username.txt);
    av_setf(avc, AV_A_TIMESTAMP, "%d", session->session_id);
    av_set(avc, AV_A_TACTYPE, (char *) type);
    av_set(avc, AV_A_SERVERIP, session->ctx->device_addr_ascii.txt);
    if (session->passwd_changeable)
	av_set(avc, AV_A_CALLER_CAP, ":chpw:");
    if (session->nac_addr_valid)
	av_set(avc, AV_A_IPADDR, session->nac_addr_ascii.txt);
    if (r->name.txt)
	av_set(avc, AV_A_REALM, r->name.txt);

    if (session->password && strcmp(type, AV_V_TACTYPE_INFO))
	av_set(avc, AV_A_PASSWORD, session->password);
    if (session->password_new && !strcmp(type, AV_V_TACTYPE_CHPW))
	av_set(avc, AV_A_PASSWORD_NEW, session->password_new);

    if (!session->ctx->realm->caching_period && !strcmp(type, AV_V_TACTYPE_INFO) && session->author_data) {
	struct author_data *data = session->author_data;
	int len = 0, cnt = data->in_cnt - 1;
	size_t *arglen = alloca(data->in_cnt * sizeof(size_t));
	for (int i = 0; i < data->in_cnt; i++) {
	    arglen[i] = strlen(data->in_args[i]);
	    len += arglen[i] + 1;
	}
	char *args = alloca(len);
	char *p = args;
	for (int i = 0; i <= cnt; i++) {
	    memcpy(p, data->in_args[i], arglen[i]);
	    p += arglen[i];
	    *p++ = (i == cnt) ? 0 : '\n';
	}
	av_set(avc, AV_A_ARGS, args);
    }

    int custom_attrs[4] = { AV_A_CUSTOM_0, AV_A_CUSTOM_1, AV_A_CUSTOM_2, AV_A_CUSTOM_3 };

    session->eval_log_raw = 1;
    for (int i = 0; i < 4; i++)
	if (session->ctx->realm->mavis_custom_attr[i])
	    av_set(avc, custom_attrs[i], eval_log_format(session, session->ctx, NULL, session->ctx->realm->mavis_custom_attr[i], io_now.tv_sec, NULL));
    session->eval_log_raw = 0;

    int result = mavis_send(mcx, &avc);

    switch (result) {
    case MAVIS_DEFERRED:
	session->mavis_pending = 1;
    case MAVIS_IGNORE:
	break;
    default:
	mavis_switch(session, avc, result);
    }
}

static int parse_user_profile_multi(av_ctx *avc, struct sym *sym, tac_user *u, char *format, int attribute)
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

static inline int parse_user_profile_single(av_ctx *avc, struct sym *sym, tac_user *u, char *format, int attribute)
{
    char *a = av_get(avc, attribute);
    if (a)
	return parse_user_profile_fmt(sym, u, format, strlen(a), a);
    return 0;
}

static __inline__ long long timediff(struct timeval *start)
{
    return (io_now.tv_sec - start->tv_sec) * 1000 + (io_now.tv_usec - start->tv_usec) / 1000;
}

static void dump_av_pairs(tac_session *session, av_ctx *avc, char *what)
{
    if (common_data.debug & (DEBUG_MAVIS_FLAG | DEBUG_TACTRACE_FLAG)) {
	int show[] = { AV_A_USER, AV_A_DN, AV_A_TACMEMBER, AV_A_MEMBEROF, AV_A_USER_RESPONSE, AV_A_SERVERIP,
	    AV_A_IPADDR, AV_A_REALM, AV_A_TACPROFILE, AV_A_SSHKEY, AV_A_SSHKEYHASH, AV_A_SSHKEYID, AV_A_PATH,
	    AV_A_UID, AV_A_GID, AV_A_HOME, AV_A_ROOT, AV_A_SHELL, AV_A_GIDS, AV_A_PASSWORD_MUSTCHANGE, AV_A_ARGS,
	    AV_A_RARGS, AV_A_VERDICT, AV_A_IDENTITY_SOURCE, AV_A_CUSTOM_0, AV_A_CUSTOM_1, AV_A_CUSTOM_2, AV_A_CUSTOM_3,
	    AV_A_COMMENT, -1
	};
	report(session, LOG_DEBUG, ~0, "%s av pairs:", what);
	for (int i = 0; show[i] > -1; i++)
	    if (avc->arr[show[i]])
		report_string(session, LOG_DEBUG, DEBUG_MAVIS_FLAG | DEBUG_TACTRACE_FLAG, av_char[show[i]].name, avc->arr[show[i]],
			      strlen(avc->arr[show[i]]));
    }
}

static void mavis_lookup_final(tac_session *session, av_ctx *avc)
{
    char *t, *result = NULL;
    tac_realm *r = session->ctx->realm;

    session->mavisauth_res = S_unknown;

    dump_av_pairs(session, avc, "user");
    if ((t = av_get(avc, AV_A_TYPE)) && !strcmp(t, AV_V_TYPE_TACPLUS) &&	//
	(t = av_get(avc, AV_A_TACTYPE)) && !strcmp(t, session->mavis_data->mavistype) &&	//
	(t = av_get(avc, AV_A_USER)) && !strcmp(t, session->username.txt) &&	//
	(t = av_get(avc, AV_A_TIMESTAMP)) && (atoi(t) == session->session_id) &&	//
	(result = av_get(avc, AV_A_RESULT)) && !strcmp(result, AV_V_RESULT_OK)) {

	tac_user *u = lookup_user(session);

	if (u)
	    r = u->realm;

	if ((r->mavis_userdb == TRISTATE_YES) && (!u || u->dynamic)) {
	    char *verdict = av_get(avc, AV_A_VERDICT);
	    if (verdict && !session->ctx->realm->caching_period && !strcmp(verdict, AV_V_BOOL_TRUE))
		session->authorized = 1;

	    if (!u || u->dynamic) {
		struct sym sym = {.filename = session->username.txt,.line = 1,.flag_prohibit_include = 1 };

		if (!r->caching_period && session->user) {
		    free_user(session->user);
		    session->user = NULL;
		}

		u = new_user(session->username.txt, S_mavis, r);
		tac_realm *rf = r;
		while (rf) {
		    if (rf->usertable) {
			rb_node_t *rbn = RB_search(rf->usertable, u);
			if (rbn) {
			    tac_user *uf = RB_payload(rbn, tac_user *);
			    if (uf->fallback_only) {
				free_user(u);
				report(session, LOG_DEBUG, DEBUG_AUTHEN_FLAG, "Not in emergency mode, ignoring user %s", uf->name.txt);
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
		    parse_user_profile_single(avc, &sym, u, "%.*s", AV_A_TACPROFILE)
		    ) {

		    free_user(u);
		    session->user = NULL;
		    session->mavisauth_res = S_deny;

		    static struct log_item *li_mavis_parse_error = NULL;
		    if (!li_mavis_parse_error)
			li_mavis_parse_error = parse_log_format_inline(session->ctx->host->user_messages[UM_MAVIS_PARSE_ERROR], __FILE__, __LINE__);
		    session->user_msg.txt = eval_log_format(session, session->ctx, NULL, li_mavis_parse_error, io_now.tv_sec, &session->user_msg.len);
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
			    session->mavisauth_res = S_deny;
			    result = AV_V_RESULT_FAIL;
			    report(session, LOG_ERR, ~0, "profile for user %s conflicts with MAVIS authentication", session->username.txt);
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
		    session->mavis_latency = timediff(&session->mavis_data->start);
		    report(session, LOG_INFO_MAVIS, ~0, "result for user %s is %s [%lu ms]", session->username.txt, result, session->mavis_latency);
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
		session->challenge = mem_strdup(session->mem, chal);
	    } else
		u->chalresp = TRISTATE_NO;
	    return;
	}

	if (strcmp(session->mavis_data->mavistype, AV_V_TACTYPE_INFO)) {
	    session->mavisauth_res = S_permit;
	    if ((TRISTATE_YES != u->chalresp) && session->password && !u->passwd_oneshot) {
		char *pass = session->password_new ? session->password_new : session->password;
		char *crypt, salt[13];
		salt[0] = '$';
		salt[1] = '1';
		salt[2] = '$';
		for (int i = 3; i < 11; i++)
		    salt[i] = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"[random() % 64];
		salt[11] = '$';
		salt[12] = 0;
		crypt = md5crypt(pass, salt);
		u->passwd[PW_MAVIS] = mem_alloc(u->mem, sizeof(struct pwdat) + strlen(crypt));
		strcpy(u->passwd[PW_MAVIS]->value, crypt);
		u->passwd[PW_MAVIS]->type = S_crypt;
		u->passwd[session->mavis_data->pw_ix] = u->passwd[PW_MAVIS];
	    }
	}
    } else if (result && !strcmp(result, AV_V_RESULT_ERROR)) {
	session->mavisauth_res = S_error;
	r->last_backend_failure = io_now.tv_sec;
	while (r && session->mavisauth_res) {
	    if (r->usertable) {
		tac_user u = {.name = session->username };
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
	session->mavisauth_res = S_deny;
    }
    if (result) {
	session->mavis_latency = timediff(&session->mavis_data->start);
	report(session, LOG_INFO_MAVIS, ~0, "result for user %s is %s [%lu ms]", session->username.txt, result, session->mavis_latency);
    }
}

static void mavis_ctx_lookup_final(struct context *, av_ctx *);

static void mavis_ctx_switch(struct context *ctx, av_ctx *avc, int result)
{
    switch (result) {
    case MAVIS_FINAL:
	ctx->mavis_pending = 0;
	mavis_ctx_lookup_final(ctx, avc);
	ctx->mavis_data->mavisfn(ctx);
	break;
    case MAVIS_TIMEOUT:
	// report(session, LOG_INFO_MAVIS, ~0, "auth_mavis: giving up (%s)", session->username);
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

#if defined(WITH_SSL)
void dump_hex(u_char *data, size_t data_len, char **buf)
{
    char hex[16] = "0123456789abcdef";
    for (size_t i = 0; i < data_len; i++) {
	if (i)
	    *(*buf)++ = ':';

	*(*buf)++ = hex[data[i] >> 4];
	*(*buf)++ = hex[data[i] & 15];
    }
}
#endif

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
    report(&session, LOG_INFO_MAVIS, ~0, "looking for host %s in MAVIS backend", ctx->device_addr_ascii.txt);

    if (!ctx->mavis_data)
	ctx->mavis_data = mem_alloc(ctx->mem, sizeof(struct mavis_data));

    ctx->mavis_data->mavisfn = f;
    ctx->mavis_data->mavistype = type;
    ctx->mavis_data->start = io_now;

    av_ctx *avc = av_new((void *) mavis_ctx_callback, (void *) ctx);
    av_set(avc, AV_A_TYPE, AV_V_TYPE_TACPLUS);
    av_set(avc, AV_A_USER, ctx->device_addr_ascii.txt);
    av_set(avc, AV_A_TACTYPE, (char *) type);	// "HOST"
    av_set(avc, AV_A_REALM, ctx->realm->name.txt);

#if defined(WITH_SSL)
    if (ctx->tls) {
	if (ctx->tls_peer_cert_subject.txt)
	    av_set(avc, AV_A_CERTSUBJ, (char *) ctx->tls_peer_cert_subject.txt);

#define SAN_PREFIX "san=\""
#define SHA1_PREFIX "sha1=\""
#define SHA256_PREFIX "sha256=\""
#define RPK_PREFIX "rpk=\""
#define ISSUER_PREFIX "issuer=\""
#define SERIAL_PREFIX "serial=\""
#define SEQ_SUFFIX "\","
	size_t len = 0;

	if (ctx->tls_peer_cert_issuer.txt)
	    len += sizeof(ISSUER_PREFIX) + sizeof(SEQ_SUFFIX) + ctx->tls_peer_cert_issuer.len;
	if (ctx->tls_peer_serial.txt)
	    len += sizeof(SERIAL_PREFIX) + sizeof(SEQ_SUFFIX) + ctx->tls_peer_serial.len;

	for (struct fingerprint * fp = ctx->fingerprint; fp; fp = fp->next) {
	    if (fp->type == S_tls_peer_cert_sha1) {
		len += sizeof(SHA1_PREFIX) + sizeof(SEQ_SUFFIX) + 3 * SHA_DIGEST_LENGTH;
		continue;
	    }
	    if (fp->type == S_tls_peer_cert_sha256) {
		len += sizeof(SHA256_PREFIX) + sizeof(SEQ_SUFFIX) + 3 * SHA256_DIGEST_LENGTH;
		continue;
	    }
	    if (fp->type == S_tls_peer_cert_rpk) {
		len += sizeof(RPK_PREFIX) + sizeof(SEQ_SUFFIX) + 3 * fp->rpk_len;
		continue;
	    }
	}


	char *u = NULL;
	char *t = NULL;
	if (ctx->tls_peer_cert_san_count) {
	    size_t *la = alloca(ctx->tls_peer_cert_san_count * sizeof(size_t));
	    len += ctx->tls_peer_cert_san_count * (sizeof(SAN_PREFIX) + sizeof(SEQ_SUFFIX));
	    for (size_t i = 0; i < ctx->tls_peer_cert_san_count; i++) {
		la[i] = strlen(ctx->tls_peer_cert_san[i]);
		len += la[i];
	    }
	    t = alloca(len);
	    u = t;
	    for (size_t i = 0; i < ctx->tls_peer_cert_san_count; i++) {
		memcpy(u, SAN_PREFIX, sizeof(SAN_PREFIX) - 1);
		u += sizeof(SAN_PREFIX) - 1;
		memcpy(u, ctx->tls_peer_cert_san[i], la[i]);
		u += la[i];
		memcpy(u, SEQ_SUFFIX, sizeof(SEQ_SUFFIX) - 1);
		u += sizeof(SEQ_SUFFIX) - 1;
	    }
	}

	if (!t) {
	    t = alloca(len);
	    u = t;
	}

	if (ctx->tls_peer_cert_issuer.txt) {
	    memcpy(u, ISSUER_PREFIX, sizeof(ISSUER_PREFIX) - 1);
	    u += sizeof(ISSUER_PREFIX) - 1;
	    memcpy(u, ctx->tls_peer_cert_issuer.txt, ctx->tls_peer_cert_issuer.len);
	    u += ctx->tls_peer_cert_issuer.len;
	    memcpy(u, SEQ_SUFFIX, sizeof(SEQ_SUFFIX) - 1);
	    u += sizeof(SEQ_SUFFIX) - 1;
	}

	if (ctx->tls_peer_serial.txt) {
	    memcpy(u, SERIAL_PREFIX, sizeof(SERIAL_PREFIX) - 1);
	    u += sizeof(SERIAL_PREFIX) - 1;
	    memcpy(u, ctx->tls_peer_serial.txt, ctx->tls_peer_serial.len);
	    u += ctx->tls_peer_serial.len;
	    memcpy(u, SEQ_SUFFIX, sizeof(SEQ_SUFFIX) - 1);
	    u += sizeof(SEQ_SUFFIX) - 1;
	}

	for (struct fingerprint * fp = ctx->fingerprint; fp; fp = fp->next) {
	    if (fp->type == S_tls_peer_cert_sha1) {
		memcpy(u, SHA1_PREFIX, sizeof(SHA1_PREFIX) - 1);
		u += sizeof(SHA1_PREFIX) - 1;
		dump_hex(fp->hash, SHA_DIGEST_LENGTH, &u);
		memcpy(u, SEQ_SUFFIX, sizeof(SEQ_SUFFIX) - 1);
		u += sizeof(SEQ_SUFFIX) - 1;
		continue;
	    }
	    if (fp->type == S_tls_peer_cert_sha256) {
		memcpy(u, SHA256_PREFIX, sizeof(SHA256_PREFIX) - 1);
		u += sizeof(SHA256_PREFIX) - 1;
		dump_hex(fp->hash, SHA256_DIGEST_LENGTH, &u);
		memcpy(u, SEQ_SUFFIX, sizeof(SEQ_SUFFIX) - 1);
		u += sizeof(SEQ_SUFFIX) - 1;
		continue;
	    }
	    if (fp->type == S_tls_peer_cert_rpk) {
		memcpy(u, RPK_PREFIX, sizeof(RPK_PREFIX) - 1);
		u += sizeof(RPK_PREFIX) - 1;
		dump_hex(fp->rpk, fp->rpk_len, &u);
		memcpy(u, SEQ_SUFFIX, sizeof(SEQ_SUFFIX) - 1);
		u += sizeof(SEQ_SUFFIX) - 1;
		continue;
	    }
	}
	u--;			// trailing comma
	*u = 0;

	if (t)
	    av_set(avc, AV_A_CERTDATA, t);
    }
#endif

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

static void mavis_ctx_lookup_final(struct context *ctx, av_ctx *avc)
{
    char *t, *result = NULL;
    tac_session session = {.ctx = ctx };
    dump_av_pairs(&session, avc, "host");
    ctx->mavis_result = S_deny;
    if ((t = av_get(avc, AV_A_TYPE)) && !strcmp(t, AV_V_TYPE_TACPLUS) &&	//
	(t = av_get(avc, AV_A_TACTYPE)) && !strcmp(t, ctx->mavis_data->mavistype) &&	//
	(t = av_get(avc, AV_A_USER)) && !strcmp(t, ctx->device_addr_ascii.txt) &&	//
	(result = av_get(avc, AV_A_RESULT)) && !strcmp(result, AV_V_RESULT_OK)) {

	ctx->mavis_result = S_permit;

	char *profile = av_get(avc, AV_A_TACPROFILE);
	if (profile) {
	    tac_host *h = mem_alloc(ctx->mem, sizeof(tac_host));
	    h->mem = ctx->mem;
	    init_host(h, ctx->host, ctx->realm, 0);

	    struct sym sym = { 0 };
	    sym.filename = ctx->device_addr_ascii.txt;
	    sym.line = 1;
	    sym.flag_prohibit_include = 1;
	    sym.in = sym.tin = profile;
	    sym.len = sym.tlen = strlen(profile);
	    if (parse_host_profile(&sym, ctx->realm, h))
		ctx->mavis_result = S_deny;
	    else {
		if (!h->name.txt)
		    h->name = ctx->host->name;
		complete_host(h);
		ctx->host = h;
	    }
	}
    }
    if (result) {
	ctx->mavis_latency = timediff(&ctx->mavis_data->start);
	report(&session, LOG_INFO_MAVIS, ~0, "result for host %s is %s [%lu ms]", ctx->device_addr_ascii.txt, result, ctx->mavis_latency);
    }
}

static void mavis_dacl_lookup_final(tac_session *, av_ctx *);

static void mavis_dacl_switch(tac_session *session, av_ctx *avc, int result)
{
    switch (result) {
    case MAVIS_FINAL:
	session->mavis_pending = 0;
	mavis_dacl_lookup_final(session, avc);
	av_free_private(avc);
	if (session->user) {
	    if (session->user->avc)
		av_free(session->user->avc);
	    session->user->avc = avc;
	}
	session->mavis_data->mavisfn(session);
	break;
    case MAVIS_TIMEOUT:
	report(session, LOG_INFO_MAVIS, ~0, "auth_mavis: giving up (%s)", session->username.txt);
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

static void mavis_dacl_callback(tac_session *session)
{
    av_ctx *avc = NULL;
    int rc = mavis_recv(lookup_mcx(session->ctx->realm), &avc, session);
    mavis_dacl_switch(session, avc, rc);
}

void mavis_dacl_lookup(tac_session *session, void (*f)(tac_session *), const char *const type)
{
    tac_realm *r = session->ctx->realm;
    mavis_ctx *mcx = lookup_mcx(r);

    if (!mcx) {
	f(session);
	return;
    }

    if (session->mavis_pending)
	return;

    if ((r->mavis_userdb != TRISTATE_YES) && !session->user) {
	f(session);
	return;
    }

    report(session, LOG_INFO_MAVIS, ~0, "looking for dacl %s in MAVIS backend", session->username.txt);

    if (!session->mavis_data)
	session->mavis_data = mem_alloc(session->mem, sizeof(struct mavis_data));

    session->mavis_data->mavisfn = f;
    session->mavis_data->mavistype = type;
    session->mavis_data->start = io_now;

    av_ctx *avc = av_new((void *) mavis_dacl_callback, (void *) session);
    av_set(avc, AV_A_TYPE, AV_V_TYPE_TACPLUS);
    av_set(avc, AV_A_USER, session->username.txt);
    av_setf(avc, AV_A_TIMESTAMP, "%d", session->session_id);
    av_set(avc, AV_A_TACTYPE, (char *) type);
    if (r->name.txt)
	av_set(avc, AV_A_REALM, r->name.txt);

    int result = mavis_send(mcx, &avc);

    switch (result) {
    case MAVIS_DEFERRED:
	session->mavis_pending = 1;
    case MAVIS_IGNORE:
	break;
    default:
	mavis_switch(session, avc, result);
    }
}

static void mavis_dacl_lookup_final(tac_session *session, av_ctx *avc)
{
    char *t, *result = NULL;
    tac_realm *r = session->ctx->realm;

    session->mavisauth_res = S_unknown;

    dump_av_pairs(session, avc, "user");
    if ((t = av_get(avc, AV_A_TYPE)) && !strcmp(t, AV_V_TYPE_TACPLUS) &&	//
	(t = av_get(avc, AV_A_TACTYPE)) && !strcmp(t, AV_V_TACTYPE_DACL) &&	//
	(t = av_get(avc, AV_A_USER)) && !strcmp(t, session->username.txt) &&	//
	(t = av_get(avc, AV_A_TIMESTAMP)) && (atoi(t) == session->session_id) &&	//
	(result = av_get(avc, AV_A_RESULT)) && !strcmp(result, AV_V_RESULT_OK)) {

	struct rad_dacl *dacl = lookup_dacl(session->username.txt, r);
	if (dacl) {
	    r = dacl->realm;
	    RB_search_and_delete(r->dacls, dacl);
	}

	struct sym sym = {.filename = session->username.txt,.line = 1,.flag_prohibit_include = 1 };

	if (!r->caching_period && session->user) {
	    free_user(session->user);
	    session->user = NULL;
	}

	char *p = av_get(avc, AV_A_TACPROFILE);
	if (!p || parse_dacl_fmt(&sym, session, r, p)) {
	    session->radius_data->dacl = NULL;
	    session->mavisauth_res = S_deny;
	}

	if (strcmp(result, AV_V_RESULT_OK)) {
	    session->mavis_latency = timediff(&session->mavis_data->start);
	    report(session, LOG_INFO_MAVIS, ~0, "result for dacl %s is %s [%lu ms]", session->username.txt, result, session->mavis_latency);
	    return;
	}
    } else if (result && !strcmp(result, AV_V_RESULT_ERROR)) {
	session->mavisauth_res = S_deny;
    } else if (result && !strcmp(result, AV_V_RESULT_FAIL)) {
	session->mavisauth_res = S_deny;
    }
    if (result) {
	session->mavis_latency = timediff(&session->mavis_data->start);
	report(session, LOG_INFO_MAVIS, ~0, "result for dacl %s is %s [%lu ms]", session->username.txt, result, session->mavis_latency);
    }
}

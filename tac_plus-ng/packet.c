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
#include "misc/mymd5.h"
#ifdef WITH_SSL
#include <openssl/hmac.h>
#include <openssl/evp.h>
#endif

static const char rcsid[] __attribute__((used)) = "$Id$";

static void write_packet(struct context *, tac_pak *);
static tac_session *new_session(struct context *, tac_pak_hdr *, rad_pak_hdr *);

static void md5_xor(tac_pak_hdr *hdr, char *key, int keylen)
{
    if (key && *key) {
	u_char *data = tac_payload(hdr, u_char *);
	int data_len = ntohl(hdr->datalength), h = 0;
	u_char hash[MD5_LEN][2];

	for (int i = 0; i < data_len; i += 16) {
	    int min = minimum(data_len - i, 16);
	    struct iovec iov[5] = {
		{.iov_base = &hdr->session_id,.iov_len = sizeof(hdr->session_id) },
		{.iov_base = key,.iov_len = keylen },
		{.iov_base = &hdr->version,.iov_len = sizeof(hdr->version) },
		{.iov_base = &hdr->seq_no,.iov_len = sizeof(hdr->seq_no) },
		{.iov_base = hash[h ^ 1],.iov_len = MD5_LEN }
	    };
	    md5v(hash[h], MD5_LEN, iov, i ? 5 : 4);

	    for (int j = 0; j < min; j++)
		data[i + j] ^= hash[h][j];
	    h ^= 1;
	}
	hdr->flags ^= TAC_PLUS_UNENCRYPTED_FLAG;
    }
}

static tac_pak *new_pak(tac_session *session, u_char type, int len)
{
    tac_pak *pak = mem_alloc(session->ctx->mem, sizeof(struct tac_pak) + len);
    pak->length = TAC_PLUS_HDR_SIZE + len;
    pak->pak.tac.type = type;
    pak->pak.tac.flags = TAC_PLUS_UNENCRYPTED_FLAG;
    pak->pak.tac.seq_no = ++session->seq_no;
    pak->pak.tac.version = session->version;
    pak->pak.tac.session_id = session->session_id;
    pak->pak.tac.datalength = htonl(len);
    return pak;
}

static void set_response_authenticator(tac_session * session, rad_pak_hdr * pak);

static tac_pak *new_rad_pak(tac_session *session, u_char code)
{
#ifdef WITH_SSL
    if (code == RADIUS_CODE_ACCESS_ACCEPT || code == RADIUS_CODE_ACCESS_REJECT)
	session->radius_data->data_len += 18;
#endif
    int len = session->radius_data->data_len + RADIUS_HDR_SIZE;
    tac_pak *pak = mem_alloc(session->ctx->mem, sizeof(struct tac_pak) + len);
    pak->length = len;
    pak->pak.rad.code = code;
    pak->pak.rad.identifier = session->radius_data->pak_in->identifier;
    pak->pak.rad.length = htons((uint16_t) (session->radius_data->data_len + RADIUS_HDR_SIZE));
    u_char *data = RADIUS_DATA(&pak->pak.rad);
    memcpy(data, session->radius_data->data, session->radius_data->data_len);

#ifdef WITH_SSL
    if (code == RADIUS_CODE_ACCESS_ACCEPT || code == RADIUS_CODE_ACCESS_REJECT) {
	memcpy(pak->pak.rad.authenticator, session->radius_data->pak_in->authenticator, 16);
	u_char *ma = data + session->radius_data->data_len - 18;
	*ma++ = RADIUS_A_MESSAGE_AUTHENTICATOR;
	*ma++ = 18;
	u_int ma_len = 16;
	HMAC(EVP_md5(), session->ctx->key->key, session->ctx->key->len, (const unsigned char *) &pak->pak.rad, len, ma, &ma_len);
	memset(pak->pak.rad.authenticator, 0, 16);
    }
#endif

    set_response_authenticator(session, &pak->pak.rad);
    return pak;
}

/* send an accounting response packet */
void send_acct_reply(tac_session *session, u_char status, char *msg, char *data)
{
    int msg_len = msg ? (int) strlen(msg) : 0;
    int data_len = data ? (int) strlen(data) : 0;
    int len = TAC_ACCT_REPLY_FIXED_FIELDS_SIZE + msg_len + data_len;

    tac_pak *pak = new_pak(session, TAC_PLUS_ACCT, len);

    struct acct_reply *reply = tac_payload(&pak->pak.tac, struct acct_reply *);
    reply->status = status;
    reply->msg_len = htons((u_short) msg_len);
    reply->data_len = htons((u_short) data_len);

    u_char *p = (u_char *) reply + TAC_ACCT_REPLY_FIXED_FIELDS_SIZE;
    memcpy(p, msg, msg_len);
    p += msg_len;
    memcpy(p, data, data_len);

    write_packet(session->ctx, pak);
    cleanup_session(session);
}

/* send an authorization reply packet */
void send_author_reply(tac_session *session, u_char status, char *msg, char *data, int arg_cnt, char **args)
{
    int msg_len = msg ? (int) strlen(msg) : 0;
    int data_len = data ? (int) strlen(data) : 0;
    size_t j = arg_cnt * sizeof(int);
    int *arglen = alloca(j);
    int user_msg_len = session->user_msg.txt ? (int) strlen(session->user_msg.txt) : 0;

    if ((user_msg_len + msg_len) & ~0xffff)
	user_msg_len = 0;

    msg_len += user_msg_len;

    msg_len = minimum(msg_len, 0xffff);
    data_len = minimum(data_len, 0xffff);

    int len = TAC_AUTHOR_REPLY_FIXED_FIELDS_SIZE + msg_len + data_len;

    for (int i = 0; i < arg_cnt; i++) {
	arglen[i] = (int) strlen(args[i]);
	len += arglen[i] + 1;
    }

    tac_pak *pak = new_pak(session, TAC_PLUS_AUTHOR, len);

    struct author_reply *reply = tac_payload(&pak->pak.tac, struct author_reply *);
    reply->status = status;
    reply->msg_len = htons((u_short) msg_len);
    reply->data_len = htons((u_short) data_len);
    reply->arg_cnt = arg_cnt;
    session->arg_out_cnt = reply->arg_cnt;

    u_char *p = (u_char *) reply + TAC_AUTHOR_REPLY_FIXED_FIELDS_SIZE;

    session->arg_out_len = (u_char *) p;

    /* place arg sizes into packet  */
    for (int i = 0; i < arg_cnt; i++)
	*p++ = arglen[i];

    if (user_msg_len) {
	memcpy(p, session->user_msg.txt, user_msg_len);
	p += user_msg_len;
    }
    memcpy(p, msg, msg_len - user_msg_len);

    p += msg_len - user_msg_len;
    memcpy(p, data, data_len);
    p += data_len;

    session->argp_out = p;

    /* copy arg bodies into packet */
    for (int i = 0; i < arg_cnt; i++) {
	memcpy(p, args[i], arglen[i]);
	p += arglen[i];
    }

#define STATICSTR_HINT(A) \
static str_t hint_ ## A = { .txt = #A, .len = sizeof(#A) - 1 }

#define STATICSTR_MSGID(A,B) \
static str_t msgid_ ## A = { .txt = B, .len = sizeof(B) - 1 }

    STATICSTR_HINT(added);
    STATICSTR_HINT(replaced);
    STATICSTR_MSGID(pass, "AUTHZPASS");
    STATICSTR_MSGID(pass_add, "AUTHZPASS-ADD");
    STATICSTR_MSGID(replaced, "AUTHZPASS-REPL");
    STATICSTR_MSGID(fail, "AUTHZFAIL");

    switch (status) {
    case TAC_PLUS_AUTHOR_STATUS_PASS_ADD:
	session->result = &codestring[S_permit];
	session->hint = hint_added;
	if (arg_cnt) {
	    session->msgid = &msgid_pass_add;
	} else {
	    session->msgid = &msgid_pass;
	}
	break;
    case TAC_PLUS_AUTHOR_STATUS_PASS_REPL:
	session->result = &codestring[S_permit];
	session->hint = hint_replaced;
	session->msgid = &msgid_replaced;
	break;
    default:
	session->result = &codestring[S_deny];
	session->msgid = &msgid_fail;
    }

    log_exec(session, session->ctx, S_authorization, io_now.tv_sec);

    write_packet(session->ctx, pak);

    cleanup_session(session);
}

/* Send an authentication reply packet indicating an error has occurred. */

void send_authen_error(tac_session *session, char *fmt, ...)
{
    int nlen, len = 1024;
    char *msg = alloca(len);
    va_list ap;

    va_start(ap, fmt);
    nlen = vsnprintf(msg, len, fmt, ap);
    va_end(ap);
    if (len <= nlen) {
	nlen++;
	msg = alloca(nlen);
	va_start(ap, fmt);
	vsnprintf(msg, nlen, fmt, ap);
	va_end(ap);
    }

    report(session, LOG_ERR, ~0, "%s %s: %s", session->ctx->device_addr_ascii.txt, session->port.txt, msg);
    send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_ERROR, msg, 0, NULL, 0, 0);
}

static void delay_packet(struct context *, tac_pak *, int);

/* create and send an authentication reply packet from tacacs+ to a NAS */

void send_authen_reply(tac_session *session, int status, char *msg, int msg_len, u_char *data, int data_len, u_char flags)
{
    if (data && !data_len)
	data_len = (int) strlen((char *) data);
    if (msg && !msg_len)
	msg_len = (int) strlen(msg);

    msg_len = minimum(msg_len, 0xffff);
    data_len = minimum(data_len, 0xffff);

    int len = TAC_AUTHEN_REPLY_FIXED_FIELDS_SIZE + msg_len + data_len;
    tac_pak *pak = new_pak(session, TAC_PLUS_AUTHEN, len);

    struct authen_reply *reply = tac_payload(&pak->pak.tac, struct authen_reply *);
    reply->status = status;
    reply->msg_len = htons((u_short) msg_len);
    reply->data_len = htons((u_short) data_len);
    reply->flags = flags;

    u_char *p = (u_char *) reply + TAC_AUTHEN_REPLY_FIXED_FIELDS_SIZE;
    memcpy(p, msg, msg_len);
    p += msg_len;
    memcpy(p, data, data_len);

    if (status == TAC_PLUS_AUTHEN_STATUS_FAIL)
	session->authfail_delay++;
    else
	session->authfail_delay = session->authen_data->iterations;

    if (session->authfail_delay && !(common_data.debug & DEBUG_TACTRACE_FLAG))
	delay_packet(session->ctx, pak, session->authfail_delay);
    else
	write_packet(session->ctx, pak);

    switch (status) {
    case TAC_PLUS_AUTHEN_STATUS_FAIL:
    case TAC_PLUS_AUTHEN_STATUS_PASS:
    case TAC_PLUS_AUTHEN_STATUS_ERROR:
    case TAC_PLUS_AUTHEN_STATUS_FOLLOW:
	cleanup_session(session);
    }
}

static void set_response_authenticator(tac_session *session, rad_pak_hdr *pak)
{
    struct iovec iov[4] = {
	{.iov_base = pak, 4 },
	{.iov_base = session->radius_data->pak_in->authenticator,.iov_len = 16 },
	{.iov_base = RADIUS_DATA(pak),.iov_len = RADIUS_DATA_LEN(pak) },
	{.iov_base = session->ctx->key->key,.iov_len = session->ctx->key->len }
    };
    md5v(pak->authenticator, MD5_LEN, iov, 4);
}

static void rad_send_reply(tac_session *session, u_char status)
{
    tac_pak *pak = new_rad_pak(session, status);

    if ((common_data.debug | session->ctx->debug) & DEBUG_PACKET_FLAG)
	dump_rad_pak(session, &pak->pak.rad);

    if (session->authfail_delay && !(common_data.debug & DEBUG_TACTRACE_FLAG) && session->ctx->udp)
	delay_packet(session->ctx, (tac_pak *) pak, session->authfail_delay);
    else {
	tac_pak **pp;
	for (pp = &session->ctx->out; *pp; pp = &(*pp)->next);
	*pp = (tac_pak *) pak;
	io_set_o(session->ctx->io, session->ctx->sock);
    }
    cleanup_session(session);
}

void rad_send_authen_reply(tac_session *session, u_char status, char *msg)
{
    if (msg && *msg) {
	size_t msg_len = strlen(msg);
	if ((session->radius_data->data_len + 2 + msg_len < sizeof(session->radius_data->data)) && (msg_len + 2 < 256)) {
	    u_char *data = session->radius_data->data;
	    *data++ = RADIUS_A_REPLY_MESSAGE;
	    *data++ = (u_char) msg_len + 2;
	    memcpy(data, msg, msg_len);
	    session->radius_data->data_len += 2 + msg_len;
	}
    }
    rad_send_reply(session, status);
}

void rad_send_acct_reply(tac_session *session)
{
    rad_send_reply(session, RADIUS_CODE_ACCOUNTING_RESPONSE);
}

void rad_send_error(tac_session *session, uint32_t cause)
{
    if ((session->radius_data->data_len + 6 < sizeof(session->radius_data->data))) {
	u_char *data = session->radius_data->data;
	*data++ = RADIUS_A_ERROR_CAUSE;
	*data++ = 6;
	cause = htonl(cause);
	memcpy(data, &cause, 4);
	session->radius_data->data_len += 6;
    }
    rad_send_reply(session, RADIUS_CODE_PROTOCOL_ERROR);
}


static void write_delayed_packet(struct context *ctx, int cur __attribute__((unused)))
{
    while (ctx->delayed && ctx->delayed->delay_until <= io_now.tv_sec) {
	tac_pak *p = ctx->delayed->next;
	ctx->delayed->next = NULL;
	write_packet(ctx, ctx->delayed);
	ctx->delayed = p;
    }
    io_sched_del(ctx->io, ctx, (void *) write_delayed_packet);
    if (ctx->delayed)
	io_sched_add(ctx->io, ctx, (void *) write_delayed_packet, ctx->delayed->delay_until - io_now.tv_sec, 0);
}

static void delay_packet(struct context *ctx, tac_pak *p, int delay)
{
    p->delay_until = io_now.tv_sec + delay;

    tac_pak **pp;
    for (pp = &ctx->delayed; *pp && (*pp)->delay_until < p->delay_until; pp = &(*pp)->next);

    p->next = *pp;
    *pp = p;

    if (ctx->delayed == p)
	io_sched_add(ctx->io, ctx, (void *) write_delayed_packet, delay, 0);
}

/* write a packet to the wire, encrypting it */
static void write_packet(struct context *ctx, tac_pak *p)
{
    p->pak.tac.flags |= ctx->flags;

    if ((common_data.debug | ctx->debug) & DEBUG_PACKET_FLAG) {
	tac_session dummy_session = {
	    .session_id = p->pak.tac.session_id,
	    .ctx = ctx,
	    .debug = ctx->debug,
	};
	report(&dummy_session, LOG_DEBUG, DEBUG_PACKET_FLAG, "Writing %s size=%d", summarise_outgoing_packet_type(&p->pak.tac), (int) p->length);
	dump_tacacs_pak(&dummy_session, &p->pak.tac);
    }

    /* encrypt the data portion */
    if (!ctx->unencrypted_flag && ctx->key)
	md5_xor(&p->pak.tac, ctx->key->key, ctx->key->len);

    tac_pak **pp;
    for (pp = &ctx->out; *pp; pp = &(*pp)->next);
    *pp = p;

    io_set_o(ctx->io, ctx->sock);
}

static int authen_pak_looks_bogus(struct context *ctx)
{
    tac_pak_hdr *hdr = &ctx->in->pak.tac;
    struct authen_start *start = tac_payload(hdr, struct authen_start *);
    struct authen_cont *cont = tac_payload(hdr, struct authen_cont *);
    u_int datalength = ntohl(hdr->datalength);
    u_int len = (hdr->seq_no == 1)
	? (TAC_AUTHEN_START_FIXED_FIELDS_SIZE + start->user_len + start->port_len + start->rem_addr_len + start->data_len)
	: (TAC_AUTHEN_CONT_FIXED_FIELDS_SIZE + ntohs(cont->user_msg_len) + ntohs(cont->user_data_len));

    return (ctx->bug_compatibility & CLIENT_BUG_HEADER_LENGTH) ? (len > datalength) : (len != datalength);
}

static int author_pak_looks_bogus(struct context *ctx)
{
    tac_pak_hdr *hdr = &ctx->in->pak.tac;
    struct author *pak = tac_payload(hdr, struct author *);
    u_char *p = (u_char *) pak + TAC_AUTHOR_REQ_FIXED_FIELDS_SIZE;
    u_int datalength = ntohl(hdr->datalength);
    u_int len = TAC_AUTHOR_REQ_FIXED_FIELDS_SIZE + pak->user_len + pak->port_len + pak->rem_addr_len + pak->arg_cnt;

    int i;
    for (i = 0; i < (int) pak->arg_cnt && len < datalength; i++)
	len += p[i];

    return (i != pak->arg_cnt) || (ctx->bug_compatibility & CLIENT_BUG_HEADER_LENGTH) ? (len > datalength) : (len != datalength);
}

static int accounting_pak_looks_bogus(struct context *ctx)
{
    tac_pak_hdr *hdr = &ctx->in->pak.tac;
    struct acct *pak = tac_payload(hdr, struct acct *);
    u_char *p = (u_char *) pak + TAC_ACCT_REQ_FIXED_FIELDS_SIZE;
    u_int datalength = ntohl(hdr->datalength);
    u_int len = TAC_ACCT_REQ_FIXED_FIELDS_SIZE + pak->user_len + pak->port_len + pak->rem_addr_len + pak->arg_cnt;

    int i;
    for (i = 0; i < (int) pak->arg_cnt && len < datalength; i++)
	len += p[i];

    return (i != pak->arg_cnt) || (ctx->bug_compatibility & CLIENT_BUG_HEADER_LENGTH) ? (len > datalength) : (len != datalength);
}

static __inline__ tac_session *RB_lookup_session(rb_tree_t *rbt, int session_id)
{
    tac_session s = {.session_id = session_id };
    return RB_lookup(rbt, &s);
}

#ifdef WITH_SSL
static int tls_ver_ok(u_int ver, u_char v)
{
    for (; ver; ver >>= 8)
	if ((ver & 0xff) == v)
	    return -1;
    return 0;
}
#endif

void tac_read(struct context *ctx, int cur)
{
    ssize_t len;
    int detached = 0;

    ctx->last_io = io_now.tv_sec;
    context_lru_append(ctx);

    if (ctx->hdroff != TAC_PLUS_HDR_SIZE) {
#ifdef WITH_SSL
	update_bio(ctx);
	if (ctx->tls)
	    len = io_SSL_read(ctx->tls, &ctx->hdr.uchar + ctx->hdroff, TAC_PLUS_HDR_SIZE - ctx->hdroff, ctx->io, cur, (void *) tac_read);
	else
#endif
	    len = recv_inject(ctx, &ctx->hdr.uchar + ctx->hdroff, TAC_PLUS_HDR_SIZE - ctx->hdroff, 0);

	if (len < 0) {
	    if (errno != EAGAIN) {
		ctx->reset_tcp = BISTATE_YES;
		cleanup(ctx, cur);
	    }
	    return;
	}

	ctx->hdroff += len;
	if (ctx->hdroff != TAC_PLUS_HDR_SIZE)
	    return;
    }
#define CHECK_PROTOCOL(A,B) \
	if (ctx->realm->allowed_protocol_ ## A != TRISTATE_YES && ctx->aaa_protocol != S_unknown \
	 && ctx->aaa_protocol != S_ ## A && ctx->aaa_protocol != S_ ## B) { \
		ctx->reset_tcp = BISTATE_YES; \
		cleanup(ctx,cur); \
		return; \
	}

    // auto-detect radius
    if (config.rad_dict && ctx->hdroff > 0 && ctx->hdr.tac.version < TAC_PLUS_MAJOR_VER) {
#ifdef WITH_SSL
	if (ctx->tls) {
	    if (ctx->udp) {
		CHECK_PROTOCOL(radius_dtls, radius);
		ctx->aaa_protocol = S_radius_dtls;
	    } else {
		CHECK_PROTOCOL(radius_tls, radius);
		ctx->aaa_protocol = S_radius_tls;
	    }
	} else
#endif
	{
	    if (ctx->udp) {
		CHECK_PROTOCOL(radius_udp, radius);
		ctx->aaa_protocol = S_radius_udp;
	    } else {
		if (!(common_data.debug & DEBUG_TACTRACE_FLAG))
		    CHECK_PROTOCOL(radius_tcp, radius);
		ctx->aaa_protocol = S_radius_tcp;
	    }
	    if (!ctx->host->radius_key) {
		ctx->reset_tcp = BISTATE_YES;
		cleanup(ctx, cur);
		return;
	    }
	}
#ifdef WITH_SSL
	static struct tac_key *key_radsec = NULL;
	static struct tac_key *key_radius_dtls = NULL;
	if (!key_radsec) {
	    key_radsec = calloc(1, sizeof(struct tac_key) + 6);
	    key_radsec->len = 6;
	    strcpy(key_radsec->key, "radsec");
	    key_radius_dtls = calloc(1, sizeof(struct tac_key) + 11);
	    key_radius_dtls->len = 11;
	    strcpy(key_radius_dtls->key, "radius/dtls");
	}
	if (ctx->tls && ctx->use_tls)
	    ctx->key = key_radsec;
	else if (ctx->tls && ctx->use_dtls)
	    ctx->key = key_radius_dtls;
	else
#endif
	    ctx->key = ctx->host->radius_key;

	if (ctx->key && !ctx->key->next)
	    ctx->key_fixed = BISTATE_YES;

	io_set_cb_i(ctx->io, ctx->sock, (void *) rad_read);
	rad_read(ctx, ctx->sock);
	return;
    }

    if (ctx->hdroff != TAC_PLUS_HDR_SIZE)
	return;

#ifdef WITH_SSL
    if (ctx->tls) {
	CHECK_PROTOCOL(tacacs_tls, tacacs);
	ctx->aaa_protocol = S_tacacs_tls;
	int ssl_version = SSL_version(ctx->tls);
	switch (ssl_version) {
	case TLS1_2_VERSION:
	    ssl_version = 0x02;
	    break;
	case TLS1_3_VERSION:
	    ssl_version = 0x03;
	    break;
	default:
	    ssl_version = 0;
	    break;
	}
	if (!tls_ver_ok(ssl_version, ctx->tls_versions) || ssl_version != 0x03) {
	    ctx->reset_tcp = BISTATE_YES;
	    cleanup(ctx, cur);
	    return;
	}
    } else
#endif
    {
	CHECK_PROTOCOL(tacacs_tcp, tacacs);
	ctx->aaa_protocol = S_tacacs_tcp;
    }

    if ((ctx->hdr.tac.version & TAC_PLUS_MAJOR_VER_MASK) != TAC_PLUS_MAJOR_VER) {
	report(NULL, LOG_ERR, ~0, "%s: Illegal major version specified: found %d wanted %d", ctx->device_addr_ascii.txt, ctx->hdr.tac.version,
	       TAC_PLUS_MAJOR_VER);
	ctx->reset_tcp = BISTATE_YES;
	cleanup(ctx, cur);
	return;
    }
    u_int data_len = ntohl(ctx->hdr.tac.datalength);

    if (data_len & ~0xffffUL) {
	report(NULL, LOG_ERR, ~0, "%s: Illegal data size: %u", ctx->device_addr_ascii.txt, data_len);
	ctx->reset_tcp = BISTATE_YES;
	cleanup(ctx, cur);
	return;
    }
    if (!ctx->in) {
	ctx->in = mem_alloc(ctx->mem, sizeof(tac_pak) + data_len);
	ctx->in->offset = TAC_PLUS_HDR_SIZE;
	ctx->in->length = TAC_PLUS_HDR_SIZE + data_len;
	memcpy(&ctx->in->pak.tac, &ctx->hdr, TAC_PLUS_HDR_SIZE);
    }
#ifdef WITH_SSL
    update_bio(ctx);
    if (ctx->tls)
	len = io_SSL_read(ctx->tls, &ctx->in->pak.uchar + ctx->in->offset, ctx->in->length - ctx->in->offset, ctx->io, cur, (void *) tac_read);
    else
#endif
	len = recv_inject(ctx, &ctx->in->pak.uchar + ctx->in->offset, ctx->in->length - ctx->in->offset, 0);

    if (len < 0) {
	if (errno != EAGAIN) {
	    ctx->reset_tcp = BISTATE_YES;
	    cleanup(ctx, cur);
	}
	return;
    }

    ctx->in->offset += len;
    if (ctx->in->offset != ctx->in->length)
	return;

    tac_session *session = RB_lookup_session(ctx->sessions, ctx->hdr.tac.session_id);

    if (session) {
	if (session->seq_no / 2 == ctx->host->max_rounds) {
	    report(session, LOG_ERR, ~0,
		   "%s: Limit of %d rounds reached for session %.8x", ctx->device_addr_ascii.txt, (int) ctx->host->max_rounds,
		   ntohl(ctx->hdr.tac.session_id));
	    send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_ERROR, "Too many rounds.", 0, NULL, 0, 0);
	    cleanup(ctx, cur);
	    return;
	}
	session->seq_no++;
	if (!session->user_is_session_specific)
	    session->user = NULL;	/* may be outdated */
	if (session->seq_no != ctx->hdr.tac.seq_no) {
	    report(session, LOG_ERR, ~0,
		   "%s: Illegal sequence number %d (!= %d) for session %.8x",
		   ctx->device_addr_ascii.txt, (int) ctx->hdr.tac.seq_no, (int) session->seq_no, ntohl(ctx->hdr.tac.session_id));
	    cleanup(ctx, cur);
	    return;
	}
    } else {
	if (ctx->hdr.tac.seq_no == 1) {
	    session = new_session(ctx, &ctx->hdr.tac, NULL);
	    mem_attach(session->mem, mem_detach(ctx->mem, ctx->in));
	    detached++;
	} else {
	    report(NULL, LOG_ERR, ~0,
		   "%s: %s packet (sequence number: %d) for session %.8x", "Stray", ctx->device_addr_ascii.txt, (int) ctx->hdr.tac.seq_no,
		   ntohl(ctx->hdr.tac.session_id));
	    cleanup(ctx, cur);
	    return;
	}
    }

    if (
#ifdef WITH_SSL
	   (ctx->tls && !(ctx->in->pak.tac.flags & TAC_PLUS_UNENCRYPTED_FLAG) && !(session->ctx->bug_compatibility & CLIENT_BUG_TLS_OBFUSCATED))
	   || (!ctx->tls && (ctx->in->pak.tac.flags & TAC_PLUS_UNENCRYPTED_FLAG))
#else
	   (ctx->in->pak.tac.flags & TAC_PLUS_UNENCRYPTED_FLAG)
#endif
	) {
	char *msg =
#ifdef WITH_SSL
	    ctx->tls ? "Peers MUST NOT use Obfuscation with TLS." :
#endif
	    "Peers MUST use Obfuscation.";
	report(NULL, LOG_ERR, ~0, "%s: %s packet (sequence number: %d) for %ssession %.8x", "Encrypted", ctx->device_addr_ascii.txt,
	       (int) ctx->hdr.tac.seq_no,
#ifdef WITH_SSL
	       ctx->tls ? "TLS " :
#endif
	       "", ntohl(ctx->hdr.tac.session_id));
	switch (ctx->hdr.tac.type) {
	case TAC_PLUS_AUTHEN:
	    send_authen_reply(session, TAC_PLUS_AUTHEN_STATUS_ERROR, msg, 0, NULL, 0, 0);
	    break;
	case TAC_PLUS_AUTHOR:
	    send_author_reply(session, TAC_PLUS_AUTHOR_STATUS_ERROR, msg, NULL, 0, NULL);
	    break;
	case TAC_PLUS_ACCT:
	    send_acct_reply(session, TAC_PLUS_ACCT_STATUS_ERROR, msg, NULL);
	    break;
	default:
	    ;
	}
	cleanup(ctx, cur);
	return;
    }

    if (ctx->in->pak.tac.flags & TAC_PLUS_UNENCRYPTED_FLAG)
	ctx->unencrypted_flag = 1;


    if ((ctx->in->pak.tac.flags & TAC_PLUS_SINGLE_CONNECT_FLAG) && (ctx->host->single_connection == TRISTATE_YES)) {
	ctx->flags |= TAC_PLUS_SINGLE_CONNECT_FLAG;
	ctx->single_connection_flag = 1;
    }

    char msg[80];
    snprintf(msg, sizeof(msg), "Illegal packet (version=0x%.2x type=0x%.2x)", ctx->in->pak.tac.version, ctx->in->pak.tac.type);

    int more_keys = 0;
    do {
	int bogus = 0;

	if (!ctx->unencrypted_flag) {
	    if (more_keys) {
		md5_xor(&ctx->in->pak.tac, ctx->key->key, ctx->key->len);
		ctx->key = ctx->key->next;
		more_keys = 0;
	    }
	    if (ctx->key)
		md5_xor(&ctx->in->pak.tac, ctx->key->key, ctx->key->len);
	}

	switch (ctx->hdr.tac.type) {
	case TAC_PLUS_AUTHEN:
	    bogus = authen_pak_looks_bogus(ctx);
	    break;
	case TAC_PLUS_AUTHOR:
	    bogus = author_pak_looks_bogus(ctx);
	    break;
	case TAC_PLUS_ACCT:
	    bogus = accounting_pak_looks_bogus(ctx);
	    break;
	default:
	    // Unknown header type, there's no gain in checking secondary keys.
	    ;
	}

	if (bogus && !ctx->unencrypted_flag && ((more_keys = ctx->key && !ctx->key_fixed && ctx->key->next)))
	    continue;

	if ((common_data.debug | ctx->debug) & DEBUG_PACKET_FLAG)
	    dump_nas_pak(session, bogus);

	switch (ctx->hdr.tac.type) {

	case TAC_PLUS_AUTHEN:
	    if (!bogus && (ctx->in->pak.tac.version == TAC_PLUS_VER_DEFAULT || ctx->in->pak.tac.version == TAC_PLUS_VER_ONE))
		authen(session, &ctx->in->pak.tac);
	    else
		send_authen_error(session, "%s", msg);
	    break;

	case TAC_PLUS_AUTHOR:
	    if (!bogus && (ctx->in->pak.tac.version == TAC_PLUS_VER_DEFAULT || (session->ctx->bug_compatibility & CLIENT_BUG_BAD_VERSION)))
		author(session, &ctx->in->pak.tac);
	    else
		send_author_reply(session, TAC_PLUS_AUTHOR_STATUS_ERROR, msg, NULL, 0, NULL);
	    break;

	case TAC_PLUS_ACCT:
	    if (!bogus && (ctx->in->pak.tac.version == TAC_PLUS_VER_DEFAULT || (session->ctx->bug_compatibility & CLIENT_BUG_BAD_VERSION)))
		accounting(session, &ctx->in->pak.tac);
	    else
		send_acct_reply(session, TAC_PLUS_ACCT_STATUS_ERROR, msg, NULL);
	    break;

	default:
	    report(session, LOG_ERR, ~0, "%s: %s", ctx->device_addr_ascii.txt, msg);
	    cleanup_session(session);
	}
    } while (more_keys);

    if (ctx->key && ctx->key->warn && !ctx->key_fixed && (ctx->key->warn <= io_now.tv_sec))
	report(NULL, LOG_INFO, ~0, "%s uses deprecated key (line %d)", ctx->device_addr_ascii.txt, ctx->key->line);

    ctx->key_fixed = BISTATE_YES;
    if (detached)
	ctx->in = NULL;
    else
	mem_free(ctx->mem, &ctx->in);
    ctx->hdroff = 0;
}

static int rad_check_failed(struct context *ctx, u_char *p, u_char *e)
{
// Consistency check: Do the attribute lengths sum up exactly?
#ifdef WITH_SSL
    u_char *message_authenticator = NULL;
#endif
    while (p < e) {
	if (p + 1 == e || p[1] < 2)
	    break;
	if (p[0] == RADIUS_A_VENDOR_SPECIFIC) {
	    u_char *pv = p + 6;
	    u_char *ev = p + p[1];
	    while (pv < ev) {
		if (pv + 1 == ev || pv[1] < 2)
		    break;
		pv += pv[1];
	    }
	    if (pv != ev)
		break;
#ifdef WITH_SSL
	} else if (p[0] == RADIUS_A_MESSAGE_AUTHENTICATOR && p[1] == 18) {
	    message_authenticator = p + 2;
#endif
	}
	p += p[1];
    }

    if (p != e) {
	ctx->reset_tcp = BISTATE_YES;
	cleanup(ctx, -1);
	return -1;
    }
#ifdef WITH_SSL
// Packet looks sane, check message authentiator, if present
    if (message_authenticator) {
	for (; ctx->key; ctx->key = ctx->key->next) {
	    u_char ma_original[16];
	    u_char ma_calculated[16];
	    memcpy(ma_original, message_authenticator, 16);
	    memset(message_authenticator, 0, 16);
	    u_int ma_calculated_len = sizeof(ma_calculated);
	    HMAC(EVP_md5(), ctx->key->key, ctx->key->len, (const unsigned char *) &ctx->in->pak.uchar, ntohs(ctx->in->pak.rad.length),
		 ma_calculated, &ma_calculated_len);
	    memcpy(message_authenticator, ma_original, 16);
	    if (!memcmp(ma_original, ma_calculated, 16)) {
		if (ctx->key->warn && (ctx->key->warn <= io_now.tv_sec))
		    report(NULL, LOG_INFO, ~0, "%s uses deprecated radius key (line %d)", ctx->device_addr_ascii.txt, ctx->key->line);
		ctx->key_fixed = BISTATE_YES;
		return 0;
	    }
	    // Check for key change within exising connection. This is unlikely to happen, and won't happen for (D)TLS.
	    if (!ctx->tls && ctx->key_fixed && ctx->host->radius_key && ctx->host->radius_key->next) {
		ctx->key_fixed = BISTATE_NO;
		ctx->key = ctx->host->radius_key;
	    }
	}
	report(NULL, LOG_INFO, ~0, "%s uses unknown radius key", ctx->device_addr_ascii.txt);
	ctx->reset_tcp = BISTATE_YES;
	cleanup(ctx, -1);
	return -1;
    }
#endif
    return 0;
}

void rad_read(struct context *ctx, int cur)
{
    ssize_t len;
    int detached = 0;

    ctx->last_io = io_now.tv_sec;
    context_lru_append(ctx);

    if (ctx->hdroff != RADIUS_HDR_SIZE) {
#ifdef WITH_SSL
	update_bio(ctx);
	if (ctx->tls)
	    len = io_SSL_read(ctx->tls, &ctx->hdr.uchar + ctx->hdroff, RADIUS_HDR_SIZE - ctx->hdroff, ctx->io, cur, (void *) rad_read);
	else
#endif
	    len = recv_inject(ctx, &ctx->hdr.uchar + ctx->hdroff, RADIUS_HDR_SIZE - ctx->hdroff, 0);

	if (len < 0) {
	    if (errno != EAGAIN) {
		ctx->reset_tcp = BISTATE_YES;
		cleanup(ctx, cur);
	    }
	    return;
	}

	ctx->hdroff += len;
	if (ctx->hdroff != RADIUS_HDR_SIZE)
	    return;
    }

    switch (ctx->hdr.rad.code) {
    case RADIUS_CODE_ACCESS_REQUEST:
    case RADIUS_CODE_ACCOUNTING_REQUEST:
    case RADIUS_CODE_STATUS_SERVER:
	break;
    default:
	ctx->reset_tcp = BISTATE_YES;
	cleanup(ctx, cur);
	return;
    }

    u_int data_len = RADIUS_DATA_LEN(&ctx->hdr.rad);

    if (!ctx->in) {
	ctx->in = mem_alloc(ctx->mem, sizeof(tac_pak) + data_len);
	ctx->in->offset = RADIUS_HDR_SIZE;
	ctx->in->length = RADIUS_HDR_SIZE + data_len;
	memcpy(&ctx->in->pak.rad, &ctx->hdr, RADIUS_HDR_SIZE);
    }
#ifdef WITH_SSL
    update_bio(ctx);
    if (ctx->tls)
	len = io_SSL_read(ctx->tls, &ctx->in->pak.uchar + ctx->in->offset, ctx->in->length - ctx->in->offset, ctx->io, cur, (void *) rad_read);
    else
#endif
	len = recv_inject(ctx, &ctx->in->pak.uchar + ctx->in->offset, ctx->in->length - ctx->in->offset, 0);

    if (len < 0) {
	if (errno != EAGAIN) {
	    ctx->reset_tcp = BISTATE_YES;
	    cleanup(ctx, cur);
	}
	return;
    }

    ctx->in->offset += len;
    if (ctx->in->offset != ctx->in->length)
	return;

    rad_pak_hdr *pak = &ctx->in->pak.rad;

    u_char *p = RADIUS_DATA(&ctx->in->pak.rad);
    u_char *e = p + data_len;
    if (rad_check_failed(ctx, p, e))
	return;

#define RAD_PAK_SESSIONID(A) (((A)->code << 8) | (A)->identifier)
    tac_session *session = RB_lookup_session(ctx->sessions, RAD_PAK_SESSIONID(&ctx->hdr.rad));

    if (session) {
	// Currently, there's no support for multi-packet exchanges, so this is most likely
	// a retransmission. This shouldn't happen for RADSEC/TCP.
	mem_free(ctx->mem, &ctx->in);
	ctx->hdroff = 0;
	return;
    }
    session = new_session(ctx, NULL, &ctx->hdr.rad);
    mem_attach(session->mem, mem_detach(ctx->mem, ctx->in));
    detached++;

    if ((common_data.debug | ctx->debug) & DEBUG_PACKET_FLAG)
	dump_rad_pak(session, &ctx->in->pak.rad);

    if (!session->radius_data) {
	session->radius_data = mem_alloc(session->mem, sizeof(struct radius_data));
	session->radius_data->pak_in = pak;
    }

    switch (pak->code) {
    case RADIUS_CODE_ACCESS_REQUEST:
	rad_authen(session);
	break;
    case RADIUS_CODE_ACCOUNTING_REQUEST:
	rad_acct(session);
	break;
    case RADIUS_CODE_STATUS_SERVER:
	if (ctx->rad_acct)
	    rad_send_acct_reply(session);
	else
	    rad_send_authen_reply(session, RADIUS_CODE_ACCESS_ACCEPT, NULL);
	break;
    default:
	report(session, LOG_ERR, ~0, "%s: code %d is unsupported", ctx->device_addr_ascii.txt, pak->code);
	cleanup_session(session);
    }

    if (detached)
	ctx->in = NULL;
    else
	mem_free(ctx->mem, &ctx->in);
    ctx->hdroff = 0;
}

#ifdef WITH_SSL
static void ssl_shutdown_sock(struct context *ctx, int cur)
{
    int res = io_SSL_shutdown(ctx->tls, ctx->io, cur, ssl_shutdown_sock);
    if (res < 0 && errno == EAGAIN)
	return;
    SSL_free(ctx->tls);
    ctx->tls = NULL;
    if (shutdown(cur, SHUT_WR))
	cleanup(ctx, cur);	// We only get here if shutdown(2) failed.
}
#endif

void tac_write(struct context *ctx, int cur)
{
    ctx->last_io = io_now.tv_sec;
    context_lru_append(ctx);
    while (ctx->out) {
	ssize_t len;
#ifdef WITH_SSL
	if (ctx->tls)
	    len = io_SSL_write(ctx->tls, &ctx->out->pak.uchar + ctx->out->offset, ctx->out->length - ctx->out->offset, ctx->io, cur, (void *) tac_write);
	else
#endif
	    len = write(cur, &ctx->out->pak.uchar + ctx->out->offset, ctx->out->length - ctx->out->offset);

	if (len < 0) {
	    if (errno != EAGAIN)
		cleanup(ctx, cur);
	    return;
	}

	ctx->out->offset += len;
	if (ctx->out->offset == ctx->out->length) {
	    tac_pak *n = ctx->out->next;
	    mem_free(ctx->mem, &ctx->out);
	    ctx->out = n;
	}
    }
    io_clr_o(ctx->io, cur);

#ifdef WITH_SSL
    if (ctx->tls && ctx->dying && !ctx->delayed) {
	if (io_SSL_shutdown(ctx->tls, ctx->io, cur, ssl_shutdown_sock))
	    return;
    }
#endif
    // Call shutdown(2) on the socket. This will trigger cleanup() being called via
    // the event loop.
    if (ctx->dying && !ctx->delayed && shutdown(cur, SHUT_WR))
	cleanup(ctx, cur);	// We only get here if shutdown(2) failed.
}

static str_t types[] = {
    { "", 0 },
#define S "authen"
    { S, sizeof(S) - 1 },
#undef S
#define S "author"
    { S, sizeof(S) - 1 },
#undef S
#define S "acct"
    { S, sizeof(S) - 1 },
#undef S
};

static tac_session *new_session(struct context *ctx, tac_pak_hdr *tac_hdr, rad_pak_hdr *radhdr)
{
    tac_session *session = mem_alloc(ctx->mem, sizeof(tac_session));
    session->ctx = ctx;
    session->debug = ctx->debug;
    session->mem = mem_create(M_LIST);
    if (tac_hdr) {
	session->version = tac_hdr->version;
	session->session_id = tac_hdr->session_id;
	session->type = &types[tac_hdr->type & 3];
    } else {
	session->session_id = RAD_PAK_SESSIONID(radhdr);
	if (radhdr->code == RADIUS_CODE_ACCESS_REQUEST) {
	    session->type = &types[1];
	} else if (radhdr->code == RADIUS_CODE_ACCOUNTING_REQUEST) {
	    session->type = &types[3];
	}
    }
    session->seq_no = 1;
    session->session_timeout = io_now.tv_sec + ctx->host->session_timeout;
    session->password_expiry = -1;
    RB_insert(ctx->sessions, session);

    if ((ctx->host->single_connection == TRISTATE_YES) && !ctx->single_connection_flag) {
	if (ctx->single_connection_test)
	    ctx->single_connection_flag = 1;
	else
	    ctx->single_connection_test = 1;
    }

    if (session->ctx->realm->mavis_userdb != TRISTATE_YES)
	session->flag_mavis_info = 1;

    if (!(common_data.debug & DEBUG_TACTRACE_FLAG))
	report(session, LOG_DEBUG, DEBUG_PACKET_FLAG, "%sNew %s session%s", common_data.font_blue, codestring[tac_hdr ? S_tacacs : S_radius].txt,
	       common_data.font_plain);

    return session;
}

void cleanup_session(tac_session *session)
{
    struct context *ctx = session->ctx;
    mavis_ctx *mcx = lookup_mcx(ctx->realm);

#ifdef WITH_DNS
    if (session->revmap_pending) {
	tac_realm *r = session->ctx->realm;
	while (r && !r->idc)
	    r = r->parent;
	if (r)
	    io_dns_cancel(r->idc, session);
	if (session->revmap_timedout)	// retry in 10 seconds
	    add_revmap(session->ctx->realm, &session->nac_address, NULL, 10, 1);
    }
#endif

    if (session->user && session->user_is_session_specific)
	free_user(session->user);

    tac_session s = {.session_id = session->session_id };
    RB_search_and_delete(ctx->sessions, &s);

    if (session->mavis_pending && mcx)
	mavis_cancel(mcx, session);
    mem_destroy(session->mem);
    mem_free(ctx->mem, &session);
    if ((ctx->cleanup_when_idle == TRISTATE_YES)
	&& (!ctx->single_connection_flag || (die_when_idle && !RB_first(ctx->sessions) && !RB_first(ctx->shellctxcache)))) {
	if (ctx->out || ctx->delayed)	// pending output
	    ctx->dying = 1;
	else
	    cleanup(ctx, ctx->sock);
    }
}

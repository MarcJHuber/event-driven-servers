/*
   Copyright (C) 1999-2022 Marc Huber (Marc.Huber@web.de)
   All rights reserved.

   Redistribution and use in source and binary  forms,  with or without
   modification, are permitted provided  that  the following conditions
   are met:

   1. Redistributions of source code  must  retain the above copyright
      notice, this list of conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions  and  the following disclaimer in
      the  documentation  and/or  other  materials  provided  with  the
      distribution.

   3. The end-user documentation  included with the redistribution,  if
      any, must include the following acknowledgment:

          This product includes software developed by Marc Huber
	  (Marc.Huber@web.de).

      Alternately,  this  acknowledgment  may  appear  in the software
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
   ANY WAY OUT OF THE  USE OF  THIS  SOFTWARE,  EVEN IF ADVISED OF THE
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

#ifdef WITH_SSL

#include <openssl/rand.h>
#include <openssl/crypto.h>

/*
 * Attribute walkers. The RADIUS packet has already passed rad_check_failed()
 * on the receive path, but the EAP code re-validates every attribute so a
 * malformed packet cannot make it read past the buffer.
 */
static int eap_pak_attr_bounds(rad_pak_hdr *pak, u_char **p, u_char **e)
{
    size_t len;

    if (!pak)
	return 0;
    len = ntohs(pak->length);
    if (len < RADIUS_HDR_SIZE)
	return 0;
    *p = RADIUS_DATA(pak);
    *e = *p + len - RADIUS_HDR_SIZE;
    return 1;
}

int eap_has_message(rad_pak_hdr *pak)
{
    u_char *p, *e;

    if (!eap_pak_attr_bounds(pak, &p, &e))
	return 0;

    while (p + 2 <= e) {
	size_t alen = p[1];
	if (alen < 2 || alen > (size_t) (e - p))
	    return 0;
	if (p[0] == RADIUS_A_EAP_MESSAGE)
	    return 1;
	p += alen;
    }
    return 0;
}

/*
 * Concatenate the EAP-Message (79) attribute values in packet order.
 * RFC 3579 3.1 requires them to be consecutive. An EAP-Message attribute
 * with a zero-length value is EAP-Start: success with *eap_len == 0.
 * The buffer comes from the tac_session pool and is valid until the session
 * is cleaned up.
 */
static int eap_collect(tac_session *session, u_char **eap, size_t *eap_len)
    __attribute__((unused));

static int eap_collect(tac_session *session, u_char **eap, size_t *eap_len)
{
    struct radius_data *rd;
    u_char *p, *e;
    size_t total = 0, max;

    *eap = NULL;
    *eap_len = 0;

    if (!session || !session->ctx || !session->ctx->realm ||
	!session->radius_data || !session->radius_data->pak_in)
	return 0;

    rd = session->radius_data;
    if (!eap_pak_attr_bounds(rd->pak_in, &p, &e))
	return 0;

    max = (size_t) session->ctx->realm->eap_max_message;

    int seen = 0, block_done = 0;
    while (p + 2 <= e) {
	size_t alen = p[1];
	if (alen < 2 || alen > (size_t) (e - p))
	    return 0;
	if (p[0] == RADIUS_A_EAP_MESSAGE) {
	    size_t vlen = alen - 2;
	    if (block_done)
		return 0;	/* EAP-Message attributes must be consecutive */
	    seen = 1;
	    if (total + vlen > max)
		return 0;
	    total += vlen;
	} else if (seen)
	    block_done = 1;
	p += alen;
    }

    if (!seen)
	return 0;
    if (!total)
	return 1;		/* EAP-Start */

    *eap = mem_alloc(session->mem, total);
    if (!*eap)
	return 0;

    p = RADIUS_DATA(rd->pak_in);
    while (p + 2 <= e) {
	size_t alen = p[1];
	if (p[0] == RADIUS_A_EAP_MESSAGE) {
	    memcpy(*eap + *eap_len, p + 2, alen - 2);
	    *eap_len += alen - 2;
	}
	p += alen;
    }
    return 1;
}

/*
 * Return the first State (24) attribute. No State attribute is not an
 * error; zero-length State and State longer than EAP_STATE_LEN are.
 * The returned pointer refers to the RADIUS packet.
 */
static int eap_get_state(tac_session *session, const u_char **state, size_t *state_len)
    __attribute__((unused));

static int eap_get_state(tac_session *session, const u_char **state, size_t *state_len)
{
    struct radius_data *rd;
    u_char *p, *e;

    *state = NULL;
    *state_len = 0;

    if (!session || !session->radius_data || !session->radius_data->pak_in)
	return 0;

    rd = session->radius_data;
    if (!eap_pak_attr_bounds(rd->pak_in, &p, &e))
	return 0;

    while (p + 2 <= e) {
	size_t alen = p[1];
	if (alen < 2 || alen > (size_t) (e - p))
	    return 0;
	if (p[0] == RADIUS_A_STATE) {
	    size_t vlen = alen - 2;
	    if (!vlen || vlen > EAP_STATE_LEN)
		return 0;
	    *state = p + 2;
	    *state_len = vlen;
	    return 1;		/* first State attribute wins */
	}
	p += alen;
    }
    return 1;
}

struct eap_parsed {
    u_char code;
    u_char identifier;
    u_short length;		/* declared length, host byte order */
    u_char type;		/* Request/Response type; 0 for Success/Failure */
    u_char flags;		/* EAP-TLS flags, reserved bits cleared */
    const u_char *data;
    size_t data_len;
};

/*
 * Validate the EAP header per RFC 3748 and RFC 5216 3.1/3.2:
 * - at least the 4-byte header must be present;
 * - the declared length must be >= 4 and must not exceed the buffer;
 * - octets beyond the declared length are padding and are ignored;
 * - an EAP-Response/EAP-TLS with the S bit set is rejected;
 * - reserved bits are ignored on receive (cleared in *out).
 */
static int eap_parse_hdr(const u_char *eap, size_t eap_len, struct eap_parsed *out)
    __attribute__((unused));

static int eap_parse_hdr(const u_char *eap, size_t eap_len, struct eap_parsed *out)
{
    struct eap_hdr hdr;
    size_t length, off;

    if (!eap || !out || eap_len < sizeof(hdr))
	return 0;

    memcpy(&hdr, eap, sizeof(hdr));
    length = ntohs(hdr.length);
    if (length < sizeof(hdr) || length > eap_len)
	return 0;

    memset(out, 0, sizeof(*out));
    out->code = hdr.code;
    out->identifier = hdr.identifier;
    out->length = (u_short) length;

    if (hdr.code != EAP_CODE_REQUEST && hdr.code != EAP_CODE_RESPONSE) {
	out->data = eap + sizeof(hdr);
	out->data_len = length - sizeof(hdr);
	return 1;
    }

    if (length < sizeof(hdr) + 1)
	return 0;
    out->type = eap[sizeof(hdr)];
    off = sizeof(hdr) + 1;

    if (out->type == EAP_TYPE_TLS) {
	if (length < off + 1)
	    return 0;
	out->flags = eap[off];
	if (hdr.code == EAP_CODE_RESPONSE && (out->flags & EAP_TLS_FLAG_S))
	    return 0;		/* RFC 5216 3.2 */
	out->flags &= EAP_TLS_FLAG_L | EAP_TLS_FLAG_M | EAP_TLS_FLAG_S;
	off++;
    }

    out->data = eap + off;
    out->data_len = length - off;
    return 1;
}

static struct eap_session *eap_lookup(tac_realm *r, const u_char *state, size_t state_len);
static struct eap_session *eap_new_session(tac_realm *r);

/*
 * Remove an EAP session from its realm tree. Used when a session was created
 * but cannot be completed; eap_session_free() releases the payload.
 */
static void eap_drop_session(tac_realm *r, struct eap_session *es)
{
    struct eap_session key;

    if (!r->eap_sessions || !es)
	return;

    memset(&key, 0, sizeof(key));
    key.state_len = es->state_len;
    memcpy(key.state, es->state, es->state_len);
    RB_search_and_delete(r->eap_sessions, &key);
}

/*
 * Store the unauthenticated EAP-Response/Identity. eap_session_free() frees
 * identity.txt with free(), so it must not come from the tac_session pool.
 * Embedded NULs would make the stored length disagree with the C string.
 */
static int eap_store_identity(struct eap_session *es, const struct eap_parsed *parsed)
{
    char *identity;

    if (!parsed->data_len || parsed->data_len > 255)
	return 0;

    identity = malloc(parsed->data_len + 1);
    if (!identity)
	return 0;
    memcpy(identity, parsed->data, parsed->data_len);
    identity[parsed->data_len] = 0;

    if (strlen(identity) != parsed->data_len) {
	free(identity);
	return 0;
    }

    free(es->identity.txt);
    str_set(&es->identity, identity, parsed->data_len);
    return 1;
}

static int eap_nak_proposes_tls(const struct eap_parsed *parsed)
{
    size_t i;

    for (i = 0; i < parsed->data_len; i++)
	if (parsed->data[i] == EAP_TYPE_TLS)
	    return 1;
    return 0;
}

/* EAP-Failure (4-byte packet) in an Access-Reject. */
static void eap_send_failure(tac_session *session, u_char identifier)
{
    u_char pkt[sizeof(struct eap_hdr)];
    struct eap_hdr hdr = { EAP_CODE_FAILURE, identifier, htons(sizeof(pkt)) };

    memcpy(pkt, &hdr, sizeof(hdr));
    rad_send_eap_reply(session, RADIUS_CODE_ACCESS_REJECT, pkt, sizeof(pkt), NULL, 0);
}

/* EAP-Response/Nak proposing EAP-TLS, for RADIUS role reversal (RFC 3579 2.6.2). */
static void eap_send_nak(tac_session *session, u_char identifier)
{
    u_char pkt[sizeof(struct eap_hdr) + 2];
    struct eap_hdr hdr = { EAP_CODE_RESPONSE, identifier, htons(sizeof(pkt)) };

    memcpy(pkt, &hdr, sizeof(hdr));
    pkt[4] = EAP_TYPE_NAK;
    pkt[5] = EAP_TYPE_TLS;
    rad_send_eap_reply(session, RADIUS_CODE_ACCESS_REJECT, pkt, sizeof(pkt), NULL, 0);
}

/*
 * Send an EAP-Request in an Access-Challenge with the session's State. The
 * server identifier is incremented for every new request and kept in
 * es->identifier (the last identifier sent). Only EAP-TLS carries a flags
 * byte; reserved bits are zero on send (RFC 5216 3.1).
 */
static void eap_send_request(tac_session *session, struct eap_session *es,
			     u_char type, u_char flags, const u_char *data, size_t data_len)
{
    size_t len = sizeof(struct eap_hdr) + 1 + data_len;
    u_char identifier = (u_char) (es->identifier + 1);
    u_char *pkt;
    size_t off;

    if (type == EAP_TYPE_TLS)
	len++;

    pkt = mem_alloc(session->mem, len);
    if (!pkt) {
	eap_send_failure(session, identifier);
	return;
    }

    struct eap_hdr hdr = { EAP_CODE_REQUEST, identifier, htons((u_short) len) };
    memcpy(pkt, &hdr, sizeof(hdr));

    off = sizeof(hdr);
    pkt[off++] = type;
    if (type == EAP_TYPE_TLS)
	pkt[off++] = flags & (EAP_TLS_FLAG_L | EAP_TLS_FLAG_M | EAP_TLS_FLAG_S);
    if (data_len)
	memcpy(pkt + off, data, data_len);

    es->identifier = identifier;
    rad_send_eap_reply(session, RADIUS_CODE_ACCESS_CHALLENGE, pkt, len, es->state, es->state_len);
}

void eap_radius_request(tac_session *session)
{
    tac_realm *r = session->ctx->realm;
    struct eap_parsed parsed;
    struct eap_session *es;
    const u_char *state;
    u_char *eap;
    size_t eap_len, state_len;
    u_char identifier;

    if (session->ctx->radius_1_1 == BISTATE_YES) {
	eap_send_failure(session, 0);
	return;
    }

    if (!eap_collect(session, &eap, &eap_len) ||
	!eap_get_state(session, &state, &state_len)) {
	eap_send_failure(session, eap_len >= 2 ? eap[1] : 0);
	return;
    }

    /* A zero-length EAP-Message value is EAP-Start; it must not carry State. */
    if (!eap_len) {
	if (state_len) {
	    eap_send_failure(session, 0);
	    return;
	}
	es = eap_new_session(r);
	if (!es) {
	    eap_send_failure(session, 0);
	    return;
	}
	eap_send_request(session, es, EAP_TYPE_IDENTITY, 0, NULL, 0);
	return;
    }

    if (!eap_parse_hdr(eap, eap_len, &parsed)) {
	eap_send_failure(session, eap_len >= 2 ? eap[1] : 0);
	return;
    }
    identifier = parsed.identifier;

    /* EAP is client-to-server here; anything else is RADIUS role reversal. */
    if (parsed.code != EAP_CODE_RESPONSE) {
	eap_send_nak(session, identifier);
	return;
    }

    if (!state_len) {
	switch (parsed.type) {
	case EAP_TYPE_IDENTITY:
	    es = eap_new_session(r);
	    if (!es) {
		eap_send_failure(session, identifier);
		return;
	    }
	    if (!eap_store_identity(es, &parsed)) {
		eap_drop_session(r, es);
		eap_send_failure(session, identifier);
		return;
	    }
	    es->client_identifier = identifier;
	    es->success_identifier = identifier;
	    es->flags |= EAP_F_IDENTITY_SEEN;
	    eap_send_request(session, es, EAP_TYPE_TLS, EAP_TLS_FLAG_S, NULL, 0);
	    return;
	case EAP_TYPE_NAK:
	    if (!eap_nak_proposes_tls(&parsed)) {
		eap_send_failure(session, identifier);
		return;
	    }
	    es = eap_new_session(r);
	    if (!es) {
		eap_send_failure(session, identifier);
		return;
	    }
	    es->client_identifier = identifier;
	    es->success_identifier = identifier;
	    eap_send_request(session, es, EAP_TYPE_TLS, EAP_TLS_FLAG_S, NULL, 0);
	    return;
	default:
	    eap_send_failure(session, identifier);
	    return;
	}
    }

    es = eap_lookup(r, state, state_len);
    if (!es) {
	eap_send_failure(session, identifier);
	return;
    }

    es->client_identifier = identifier;
    es->success_identifier = identifier;
    es->expires = io_now.tv_sec + r->eap_timeout;
    es->last_activity = io_now.tv_sec;

    switch (parsed.type) {
    case EAP_TYPE_IDENTITY:
	/* Identity is only valid without State. */
	eap_send_failure(session, identifier);
	return;
    case EAP_TYPE_TLS:
	/* The TLS handshake is added in Task 10; keep the dispatch here. */
	eap_send_failure(session, identifier);
	return;
    case EAP_TYPE_NAK:
	if (eap_nak_proposes_tls(&parsed))
	    eap_send_request(session, es, EAP_TYPE_TLS, EAP_TLS_FLAG_S, NULL, 0);
	else
	    eap_send_failure(session, identifier);
	return;
    default:
	eap_send_failure(session, identifier);
	return;
    }
}

void eap_expire_sessions(tac_realm *r)
{
    if (r->eap_sessions) {
	rb_node_t *rbn, *next;
	for (rbn = RB_first(r->eap_sessions); rbn; rbn = next) {
	    struct eap_session *e = RB_payload(rbn, struct eap_session *);
	    next = RB_next(rbn);
	    if (e->expires < io_now.tv_sec)
		RB_delete(r->eap_sessions, rbn);
	}
    }
    if (r->realms) {
	rb_node_t *rbn;
	for (rbn = RB_first(r->realms); rbn; rbn = RB_next(rbn))
	    eap_expire_sessions(RB_payload(rbn, tac_realm *));
    }
}

void eap_session_free(void *payload)
{
    struct eap_session *e = payload;
    int i;

    if (!e)
	return;

    if (e->ssl)
	SSL_free(e->ssl);	/* frees rbio/wbio */
    free(e->in);
    free(e->tls_in);
    while (e->out) {
	struct eap_fragment *f = e->out;
	e->out = f->next;
	free(f);
    }
    for (i = 0; i < EAP_REPLY_CACHE_SIZE; i++) {
	free(e->reply_cache[i].eap);
	free(e->reply_cache[i].state);
    }
    free(e->identity.txt);
    OPENSSL_cleanse(e->msk, sizeof(e->msk));
    OPENSSL_cleanse(e->emsk, sizeof(e->emsk));
    free(e);
}

int eap_session_cmp(const void *a, const void *b)
{
    const struct eap_session *x = a, *y = b;

    if (x->state_len != y->state_len)
	return (int) x->state_len - (int) y->state_len;
    return memcmp(x->state, y->state, x->state_len);
}

static struct eap_session *eap_lookup(tac_realm *r, const u_char *state, size_t state_len)
{
    struct eap_session key;
    rb_node_t *rbn;

    if (!r->eap_sessions || state_len < 1 || state_len > EAP_STATE_LEN)
	return NULL;

    memset(&key, 0, sizeof(key));
    key.state_len = state_len;
    memcpy(key.state, state, state_len);

    rbn = RB_search(r->eap_sessions, &key);
    return rbn ? RB_payload(rbn, struct eap_session *) : NULL;
}

static struct eap_session *eap_new_session(tac_realm *r) __attribute__((unused));

static struct eap_session *eap_new_session(tac_realm *r)
{
    struct eap_session *e = calloc(1, sizeof(*e));
    u_char state[EAP_STATE_LEN];
    size_t state_len;

    if (!e)
	return NULL;

    if (RAND_bytes(e->state, EAP_STATE_LEN) != 1) {
	free(e);
	return NULL;
    }
    e->state_len = EAP_STATE_LEN;
    e->identifier = 1;
    e->expires = io_now.tv_sec + r->eap_timeout;
    e->last_activity = io_now.tv_sec;

    if (!r->eap_sessions)
	r->eap_sessions = RB_tree_new(eap_session_cmp, eap_session_free);
    if (!r->eap_sessions) {
	free(e);
	return NULL;
    }

    if (RB_count(r->eap_sessions) >= r->eap_max_sessions) {
	/* Evict the session with the oldest last_activity; RB_first() would
	   return the lexicographically smallest State, not the oldest. */
	struct eap_session *oldest = NULL;
	rb_node_t *rbn;

	for (rbn = RB_first(r->eap_sessions); rbn; rbn = RB_next(rbn)) {
	    struct eap_session *candidate = RB_payload(rbn, struct eap_session *);
	    if (!oldest || candidate->last_activity < oldest->last_activity)
		oldest = candidate;
	}
	if (oldest) {
	    struct eap_session key;

	    memset(&key, 0, sizeof(key));
	    key.state_len = oldest->state_len;
	    memcpy(key.state, oldest->state, oldest->state_len);
	    RB_search_and_delete(r->eap_sessions, &key);
	}
    }

    state_len = e->state_len;
    memcpy(state, e->state, state_len);

    if (!RB_insert(r->eap_sessions, e)) {
	/* Duplicate key: RB_insert() freed the rbnode wrapper, not the
	   payload. Free the duplicate and return the existing session. */
	eap_session_free(e);
	return eap_lookup(r, state, state_len);
    }
    return e;
}

SSL_CTX *eap_ssl_init(tac_realm *r)
{
    (void) r;
    return NULL;
}

#endif				/* WITH_SSL */

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
#include <openssl/err.h>
#include <openssl/x509v3.h>

#if OPENSSL_VERSION_NUMBER < 0x30000000L
/* OpenSSL 1.1 returns a referenced certificate under this older name. */
#define SSL_get1_peer_certificate SSL_get_peer_certificate
#endif

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

/*
 * Reply cache. RFC 5216 2.1.5: retransmitted fragments keep the same EAP
 * Identifier. A ring of the last EAP_REPLY_CACHE_SIZE replies, keyed by the
 * identifier of the request being answered, lets a retransmitted
 * Access-Request (or fragment ACK) get the exact same reply without
 * advancing the state machine. The eap_session outlives the tac_session, so
 * the cached EAP and State bytes are malloc()ed copies.
 */
static void eap_cache_reply(struct eap_session *es, u_char identifier,
			    u_char code, const u_char *eap, size_t eap_len,
			    const u_char *state, size_t state_len)
{
    struct eap_cached_reply *slot;

    if (!es)
	return;

    slot = &es->reply_cache[es->reply_cache_next];
    free(slot->eap);
    free(slot->state);
    memset(slot, 0, sizeof(*slot));
    slot->identifier = identifier;
    slot->code = code;

    if (eap_len) {
	slot->eap = malloc(eap_len);
	if (slot->eap) {
	    memcpy(slot->eap, eap, eap_len);
	    slot->eap_len = eap_len;
	}
    }
    if (state_len) {
	slot->state = malloc(state_len);
	if (slot->state) {
	    memcpy(slot->state, state, state_len);
	    slot->state_len = state_len;
	}
    }

    /* Do not leave a partial entry behind: replaying an EAP reply without
       its State would break the conversation. */
    if ((eap_len && !slot->eap) || (state_len && !slot->state)) {
	free(slot->eap);
	free(slot->state);
	memset(slot, 0, sizeof(*slot));
	slot->identifier = identifier;
	slot->code = code;
    }

    es->reply_cache_next = (es->reply_cache_next + 1) % EAP_REPLY_CACHE_SIZE;
}

static struct eap_cached_reply *eap_reply_lookup(struct eap_session *es, u_char identifier)
{
    int i;

    if (!es)
	return NULL;

    for (i = 0; i < EAP_REPLY_CACHE_SIZE; i++) {
	struct eap_cached_reply *slot = &es->reply_cache[i];

	if (slot->eap_len && slot->identifier == identifier)
	    return slot;
    }
    return NULL;
}

/*
 * Send an EAP reply tied to an EAP session and cache it first.
 * rad_send_eap_reply() frees the tac_session, so the cache must hold its
 * own copies of the EAP and State bytes.
 */
static void eap_send_reply(tac_session *session, struct eap_session *es,
			   u_char identifier, u_char code,
			   const u_char *eap, size_t eap_len,
			   const u_char *state, size_t state_len)
{
    eap_cache_reply(es, identifier, code, eap, eap_len, state, state_len);
    rad_send_eap_reply(session, code, eap, eap_len, state, state_len);
}

/* EAP-Failure (4-byte packet) in an Access-Reject. */
static void eap_send_failure(tac_session *session, struct eap_session *es, u_char identifier)
{
    u_char pkt[sizeof(struct eap_hdr)];
    struct eap_hdr hdr = { EAP_CODE_FAILURE, identifier, htons(sizeof(pkt)) };

    memcpy(pkt, &hdr, sizeof(hdr));
    eap_send_reply(session, es, identifier, RADIUS_CODE_ACCESS_REJECT, pkt, sizeof(pkt), NULL, 0);
}

/* EAP-Success (4-byte packet) in an Access-Accept. */
static void eap_send_success(tac_session *session, struct eap_session *es, u_char identifier)
{
    u_char pkt[sizeof(struct eap_hdr)];
    struct eap_hdr hdr = { EAP_CODE_SUCCESS, identifier, htons(sizeof(pkt)) };

    memcpy(pkt, &hdr, sizeof(hdr));
    eap_send_reply(session, es, identifier, RADIUS_CODE_ACCESS_ACCEPT, pkt, sizeof(pkt), NULL, 0);
}

/*
 * Copy an identity into a malloc()ed C string. Certificate-derived identities
 * are lowercased (ASCII only); the lab-only EAP-Response/Identity is used as
 * supplied. Reject empty values, embedded NULs and values over 255 bytes.
 */
static char *eap_copy_identity(const u_char *data, size_t len, int lowercase)
{
    char *identity;
    size_t i;

    if (!data || !len || len > 255 || memchr(data, 0, len))
	return NULL;

    identity = malloc(len + 1);
    if (!identity)
	return NULL;

    for (i = 0; i < len; i++) {
	u_char c = data[i];

	identity[i] = (char) (lowercase && c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c);
    }
    identity[len] = 0;
    return identity;
}

static char *eap_cert_cn(X509 *cert)
{
    X509_NAME *subject;
    X509_NAME_ENTRY *entry;
    ASN1_STRING *data;
    int idx;

    subject = X509_get_subject_name(cert);
    if (!subject)
	return NULL;

    idx = X509_NAME_get_index_by_NID(subject, NID_commonName, -1);
    if (idx < 0)
	return NULL;

    entry = X509_NAME_get_entry(subject, idx);
    if (!entry)
	return NULL;

    data = X509_NAME_ENTRY_get_data(entry);
    if (!data)
	return NULL;

    return eap_copy_identity(ASN1_STRING_get0_data(data),
			     (size_t) ASN1_STRING_length(data), 1);
}

/*
 * First GEN_DNS subjectAltName. *found distinguishes "no DNS SAN" (fall
 * back to CN) from "a DNS SAN exists but is unusable" (reject).
 */
static char *eap_cert_san(X509 *cert, int *found)
{
    GENERAL_NAMES *names;
    char *identity = NULL;
    int i;

    *found = 0;
    names = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    if (!names)
	return NULL;

    for (i = 0; i < sk_GENERAL_NAME_num(names); i++) {
	GENERAL_NAME *gn = sk_GENERAL_NAME_value(names, i);

	if (gn->type != GEN_DNS)
	    continue;
	*found = 1;
	identity = eap_copy_identity(ASN1_STRING_get0_data(gn->d.dNSName),
				     (size_t) ASN1_STRING_length(gn->d.dNSName), 1);
	break;
    }

    GENERAL_NAMES_free(names);
    return identity;
}

static char *eap_extract_identity(tac_session *session, struct eap_session *es)
{
    tac_realm *r = session->ctx->realm;
    char *identity = NULL;

    switch (r->eap_identity_source) {
    case S_cert_cn:
    case S_cert_san:
	if (es->ssl) {
	    X509 *cert = SSL_get1_peer_certificate(es->ssl);

	    if (cert) {
		if (r->eap_identity_source == S_cert_cn)
		    identity = eap_cert_cn(cert);
		else {
		    int found = 0;

		    identity = eap_cert_san(cert, &found);
		    if (!found)
			identity = eap_cert_cn(cert);
		}
		X509_free(cert);
	    }
	}
	break;
    case S_eap_identity:
	identity = eap_copy_identity((const u_char *) es->identity.txt,
				     es->identity.len, 0);
	if (identity)
	    report(session, LOG_WARNING, ~0,
		   "EAP: using unauthenticated EAP-Response/Identity for authorization");
	break;
    default:
	break;
    }
    return identity;
}

/*
 * Add the default MS-MPPE-Encryption-Policy/Types and, once the TLS
 * handshake has completed, the MSK halves as MS-MPPE-Recv-Key/Send-Key
 * (RFC 5216 2.3, RFC 2548 2.4.2). rad_add_mppe_key() encrypts with this
 * request's Request Authenticator, so an Access-Accept retransmission
 * re-encrypts the retained MSK instead of replaying cached ciphertext.
 */
#ifdef WITH_CRYPTO
static void eap_add_mppe(tac_session *session, struct eap_session *es)
{
    struct radius_data *rd = session->radius_data;

    if (!session->ctx->key || !(es->flags & EAP_F_HANDSHAKE_DONE) || !rd)
	return;

    /* Policy/Types (2 * 12) plus two 58-byte key VSAs must fit together with
       the RADIUS header and the Message-Authenticator reservation. */
    if (rd->data_len + 2 * 12 + 2 * 58 + RADIUS_HDR_SIZE + 18 > sizeof(rd->data))
	return;

    rad_add_mppe_policy(session);
    rad_add_mppe_key(session, es->msk, 32, RADIUS_A_MS_MPPE_RECV_KEY);
    rad_add_mppe_key(session, es->msk + 32, 32, RADIUS_A_MS_MPPE_SEND_KEY);
}
#endif

/*
 * Cache the profile/authorization AVPs from the reply buffer so an
 * Access-Accept/Access-Reject retransmission can replay them. The MS-MPPE
 * keys are deliberately not cached; they are re-encrypted per request.
 */
static void eap_cache_profile_attrs(struct eap_session *es, tac_session *session)
{
    struct radius_data *rd = session->radius_data;

    free(es->profile_attrs);
    es->profile_attrs = NULL;
    es->profile_attrs_len = 0;
    if (!rd || !rd->data_len)
	return;

    es->profile_attrs = malloc(rd->data_len);
    if (!es->profile_attrs)
	return;
    memcpy(es->profile_attrs, rd->data, rd->data_len);
    es->profile_attrs_len = rd->data_len;
}

/*
 * Map the completed handshake to a user and run the existing authorization
 * path. On success send EAP-Success in an Access-Accept; the profile
 * attributes are already in session->radius_data->data. On an identity
 * extraction failure or a denial send EAP-Failure in an Access-Reject.
 * rad_send_eap_reply() frees the tac_session, so do not touch it afterwards.
 */
static enum token eap_identity_authorize(tac_session *session, struct eap_session *es,
					 u_char identifier)
{
    enum hint_enum hint = hint_nosuchuser;
    enum token res;
    char *identity, *resp = NULL;

    identity = eap_extract_identity(session, es);
    if (!identity) {
	report(session, LOG_WARNING, ~0, "EAP: no usable client identity");
	es->flags |= EAP_F_FAILED;
	eap_send_failure(session, es, identifier);
	return S_deny;
    }

    str_set(&session->username, mem_strdup(session->mem, identity), 0);
    free(identity);
    if (!session->username.txt) {
	report(session, LOG_ERR, ~0, "EAP: out of memory storing client identity");
	es->flags |= EAP_F_FAILED;
	eap_send_failure(session, es, identifier);
	return S_deny;
    }

    res = eap_authorize(session, &resp, &hint);
    if (res == S_permit) {
	eap_cache_profile_attrs(es, session);
#ifdef WITH_CRYPTO
	eap_add_mppe(session, es);
#endif
	eap_send_success(session, es, identifier);
	return res;
    }

    eap_cache_profile_attrs(es, session);
    es->flags |= EAP_F_FAILED;
    eap_send_failure(session, es, identifier);
    return res;
}

/* EAP-Response/Nak proposing EAP-TLS, for RADIUS role reversal (RFC 3579 2.6.2). */
static void eap_send_nak(tac_session *session, struct eap_session *es, u_char identifier)
{
    u_char pkt[sizeof(struct eap_hdr) + 2];
    struct eap_hdr hdr = { EAP_CODE_RESPONSE, identifier, htons(sizeof(pkt)) };

    memcpy(pkt, &hdr, sizeof(hdr));
    pkt[4] = EAP_TYPE_NAK;
    pkt[5] = EAP_TYPE_TLS;
    eap_send_reply(session, es, identifier, RADIUS_CODE_ACCESS_REJECT, pkt, sizeof(pkt), NULL, 0);
}

/*
 * Send an EAP-Request in an Access-Challenge with the session's State. The
 * server identifier is incremented for every new request and kept in
 * es->identifier (the last identifier sent). Only EAP-TLS carries a flags
 * byte; reserved bits are zero on send (RFC 5216 3.1). Replies to requests
 * carrying State are cached (cache != 0) under the identifier of the request
 * being answered; replies to no-State requests are not, because those create
 * a new session and are never looked up by identifier.
 */
static void eap_send_request(tac_session *session, struct eap_session *es,
			     u_char type, u_char flags, const u_char *data, size_t data_len,
			     int cache)
{
    size_t len = sizeof(struct eap_hdr) + 1 + data_len;
    u_char identifier = (u_char) (es->identifier + 1);
    u_char *pkt;
    size_t off;

    if (type == EAP_TYPE_TLS)
	len++;

    pkt = mem_alloc(session->mem, len);
    if (!pkt) {
	eap_send_failure(session, es, identifier);
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
    if (cache)
	eap_send_reply(session, es, es->client_identifier, RADIUS_CODE_ACCESS_CHALLENGE,
		       pkt, len, es->state, es->state_len);
    else
	rad_send_eap_reply(session, RADIUS_CODE_ACCESS_CHALLENGE, pkt, len, es->state, es->state_len);
}

/*
 * Lazily create the server SSL object for an EAP session. SSL_set_bio()
 * hands the memory BIOs to the SSL object; eap_session_free() frees them
 * with SSL_free().
 */
static int eap_tls_start(struct eap_session *es, tac_realm *r)
{
    if (es->ssl)
	return 1;
    if (!r->eap_tls)
	return 0;

    es->ssl = SSL_new(r->eap_tls);
    if (!es->ssl)
	return 0;

    SSL_set_accept_state(es->ssl);
    es->rbio = BIO_new(BIO_s_mem());
    es->wbio = BIO_new(BIO_s_mem());
    if (!es->rbio || !es->wbio) {
	if (es->rbio)
	    BIO_free(es->rbio);
	if (es->wbio)
	    BIO_free(es->wbio);
	SSL_free(es->ssl);
	es->ssl = NULL;
	es->rbio = es->wbio = NULL;
	return 0;
    }

    SSL_set_bio(es->ssl, es->rbio, es->wbio);
    SSL_set_app_data(es->ssl, es);
    es->tls_state = EAP_TLS_HANDSHAKE;
    return 1;
}

/*
 * Drain all pending TLS output into a malloc()ed buffer. A certificate
 * flight is several KB, so the buffer is sized from BIO_ctrl_pending(),
 * not a fixed EAP/RADIUS packet size. *buf is NULL and *len is 0 when
 * there is nothing to send.
 */
static int eap_tls_drain(struct eap_session *es, u_char **buf, size_t *len)
{
    size_t total, got = 0;

    *buf = NULL;
    *len = 0;

    total = (size_t) BIO_ctrl_pending(es->wbio);
    if (!total)
	return 1;

    *buf = malloc(total);
    if (!*buf)
	return 0;

    while (got < total) {
	int n = BIO_read(es->wbio, *buf + got, (int) (total - got));
	if (n <= 0)
	    break;
	got += (size_t) n;
    }

    if (got != total) {
	free(*buf);
	*buf = NULL;
	return 0;
    }

    *len = got;
    return 1;
}

/*
 * Queue drained TLS output for EAP-TLS fragmentation. es->out holds the
 * whole flight; out_offset is the number of bytes already sent and
 * out_total the full length. The first fragment carries L and the total
 * length; M is set on all but the last fragment (RFC 5216 2.1.5).
 */
static int eap_tls_queue(struct eap_session *es, const u_char *buf, size_t len)
{
    struct eap_fragment *f;

    while (es->out) {
	struct eap_fragment *next = es->out->next;
	free(es->out);
	es->out = next;
    }
    es->out_offset = 0;
    es->out_total = 0;

    if (!len)
	return 1;

    f = malloc(sizeof(*f) + len);
    if (!f)
	return 0;

    f->next = NULL;
    f->len = len;
    memcpy(f->data, buf, len);
    es->out = f;
    es->out_total = len;
    return 1;
}

/*
 * Send the next EAP-Request/EAP-TLS fragment of the queued flight in an
 * Access-Challenge with State. The EAP identifier is incremented per
 * fragment; reserved bits are zero. Returns 1 on success, 0 when there is
 * nothing to send, -1 after sending EAP-Failure (the tac_session is gone).
 */
static int eap_tls_send_fragment(tac_session *session, struct eap_session *es)
{
    size_t remain, chunk, len, off;
    u_char flags = 0;
    u_char identifier;
    u_char *pkt;

    if (!es->out || es->out_offset >= es->out_total)
	return 0;

    remain = es->out_total - es->out_offset;
    chunk = remain > EAP_MAX_FRAGMENT ? EAP_MAX_FRAGMENT : remain;
    identifier = (u_char) (es->identifier + 1);

    len = sizeof(struct eap_hdr) + 2 + chunk;	/* type and flags */
    if (!es->out_offset)
	len += 4;				/* TLS Message Length */

    pkt = mem_alloc(session->mem, len);
    if (!pkt) {
	eap_send_failure(session, es, identifier);
	return -1;
    }

    struct eap_hdr hdr = { EAP_CODE_REQUEST, identifier, htons((u_short) len) };
    memcpy(pkt, &hdr, sizeof(hdr));
    off = sizeof(hdr);
    pkt[off++] = EAP_TYPE_TLS;

    if (!es->out_offset)
	flags |= EAP_TLS_FLAG_L;
    if (es->out_offset + chunk < es->out_total)
	flags |= EAP_TLS_FLAG_M;
    pkt[off++] = flags;

    if (!es->out_offset) {
	uint32_t total = htonl((uint32_t) es->out_total);

	memcpy(pkt + off, &total, sizeof(total));
	off += sizeof(total);
    }

    memcpy(pkt + off, es->out->data + es->out_offset, chunk);
    es->out_offset += chunk;
    es->identifier = identifier;

    eap_send_reply(session, es, es->client_identifier, RADIUS_CODE_ACCESS_CHALLENGE,
		   pkt, len, es->state, es->state_len);
    return 1;
}

/*
 * RFC 5216 2.1.3: a TLS alert produced by the server must be sent in an
 * EAP-Request/EAP-TLS before EAP-Failure. Walk the TLS records in the
 * drained output; anything else means OpenSSL did not produce an alert.
 */
static int eap_tls_has_alert(const u_char *buf, size_t len)
{
    size_t off = 0;

    while (off + 5 <= len) {
	size_t reclen = ((size_t) buf[off + 3] << 8) | buf[off + 4];

	if (buf[off] == SSL3_RT_ALERT)
	    return 1;
	off += 5 + reclen;
    }
    return 0;
}

/*
 * Handshake failure. Send the TLS alert, if OpenSSL produced one, in an
 * EAP-Request/EAP-TLS (Access-Challenge) and wait for the peer's response;
 * otherwise send EAP-Failure directly. The EAP session stays in the realm
 * tree: the reply helper frees the tac_session, not the eap_session.
 */
static void eap_tls_fail(tac_session *session, struct eap_session *es, const char *reason)
{
    u_char *buf = NULL;
    size_t len = 0;
    unsigned long err = ERR_get_error();

    es->flags |= EAP_F_FAILED;
    if (err) {
	char ebuf[256];
	report(session, LOG_ERR, ~0, "EAP-TLS handshake failed: %s: %s",
	       reason, ERR_error_string(err, ebuf));
    } else
	report(session, LOG_ERR, ~0, "EAP-TLS handshake failed: %s", reason);

    if (eap_tls_drain(es, &buf, &len) && len && eap_tls_has_alert(buf, len)) {
	es->tls_state = EAP_TLS_ALERT_SENT;
	es->flags |= EAP_F_ALERT_SENT;
	eap_send_request(session, es, EAP_TYPE_TLS, 0, buf, len, 1);
	free(buf);
	return;
    }

    free(buf);
    eap_send_failure(session, es, es->success_identifier);
}

/*
 * RFC 5216 2.3 / RFC 5705: export 128 bytes with the label "client EAP
 * encryption" and an empty context. MSK = bytes 0..63, EMSK = 64..127.
 * The temporary key material is cleansed and never logged.
 */
static int eap_derive_keys(tac_session *session, struct eap_session *es)
{
    u_char keymat[128];

    if (SSL_export_keying_material(es->ssl, keymat, sizeof(keymat),
				   "client EAP encryption", 21, NULL, 0, 0) != 1) {
	OPENSSL_cleanse(keymat, sizeof(keymat));
	eap_tls_fail(session, es, "key export");
	return 0;
    }

    memcpy(es->msk, keymat, sizeof(es->msk));
    memcpy(es->emsk, keymat + sizeof(es->msk), sizeof(es->emsk));
    OPENSSL_cleanse(keymat, sizeof(keymat));
    return 1;
}

/*
 * Empty EAP-Response/EAP-TLS with State: a fragment ACK or the final
 * handshake ACK (RFC 5216 2.1.5 / 2.1.3). Fragment ACKs move the queued
 * server flight forward one fragment at a time; only the ACK for the last
 * server fragment completes the handshake and allows EAP-Success.
 */
static void eap_tls_ack(tac_session *session, struct eap_session *es,
			const struct eap_parsed *parsed)
{
    int sent;

    switch (es->tls_state) {
    case EAP_TLS_FINAL_FLIGHT_SENDING:
	/* More final-flight fragments are queued: one fragment per ACK. */
	sent = eap_tls_send_fragment(session, es);
	if (sent < 0)
	    return;
	if (es->out_offset >= es->out_total)
	    es->tls_state = EAP_TLS_WAIT_FINAL_ACK;
	return;
    case EAP_TLS_HANDSHAKE:
	/* Fragment ACK for a non-final server flight. */
	sent = eap_tls_send_fragment(session, es);
	if (sent < 0)
	    return;
	if (!sent)
	    eap_send_failure(session, es, parsed->identifier);
	return;
    case EAP_TLS_WAIT_FINAL_ACK:
	if (parsed->identifier != es->identifier) {
	    eap_send_failure(session, es, parsed->identifier);
	    return;
	}
	es->tls_state = EAP_TLS_DONE;
	es->flags |= EAP_F_COMPLETED;
	es->success_identifier = parsed->identifier;
	eap_identity_authorize(session, es, parsed->identifier);
	return;
    default:
	/* ALERT_SENT and FAILED are handled by the caller; an ACK in DONE or
	   before the handshake started is a protocol error. */
	eap_send_failure(session, es, parsed->identifier);
	return;
    }
}

/*
 * Append a fragment to the EAP-TLS reassembly buffer, growing it as needed.
 * Reassembly is capped at eap_max_message (RFC 5216 2.1.5).
 */
static int eap_tls_append(struct eap_session *es, const u_char *data, size_t len, size_t max)
{
    size_t need = es->tls_len + len;

    if (need > max)
	return 0;

    if (need > es->tls_max) {
	size_t grow = es->tls_max ? es->tls_max : 4096;
	u_char *p;

	while (grow < need)
	    grow <<= 1;
	if (grow > max)
	    grow = max;

	p = realloc(es->tls_in, grow);
	if (!p)
	    return 0;
	es->tls_in = p;
	es->tls_max = grow;
    }

    if (len)
	memcpy(es->tls_in + es->tls_len, data, len);
    es->tls_len = need;
    return 1;
}

/*
 * EAP-Response/EAP-TLS with State: reassemble client fragments (RFC 5216
 * 2.1.5), feed the complete TLS message to the server SSL object and send
 * its output as EAP-Request/EAP-TLS fragments. The final TLS flight is
 * followed by a peer ACK before EAP-Success (Task 11).
 */
static void eap_tls_request(tac_session *session, struct eap_session *es,
			    const struct eap_parsed *parsed)
{
    tac_realm *r = session->ctx->realm;
    const u_char *tls_data = parsed->data;
    size_t tls_data_len = parsed->data_len;
    int reassembled = 0;
    u_char *buf = NULL;
    size_t len = 0;
    int ret, err;

    /* After an alert, RFC 5216 2.1.3 answers the peer's response with
       EAP-Failure. Restart-on-ClientHello is not implemented. */
    if (es->tls_state == EAP_TLS_ALERT_SENT || (es->flags & EAP_F_FAILED)) {
	eap_send_failure(session, es, parsed->identifier);
	return;
    }

    /* An empty EAP-Response/EAP-TLS is a fragment or completion ACK. */
    if (!parsed->data_len) {
	eap_tls_ack(session, es, parsed);
	return;
    }

    /* Non-empty TLS data is only valid while the handshake is running and
       all server fragments have been acknowledged. */
    if (es->tls_state == EAP_TLS_FINAL_FLIGHT_SENDING ||
	es->tls_state == EAP_TLS_WAIT_FINAL_ACK ||
	es->tls_state == EAP_TLS_DONE ||
	(es->out && es->out_offset < es->out_total)) {
	eap_send_failure(session, es, parsed->identifier);
	return;
    }

    /*
     * Client-to-server fragmentation (RFC 5216 2.1.5). L is only valid on
     * the first fragment and carries the 4-octet TLS Message Length; M is
     * set on all but the last fragment. A response with neither flag and no
     * pending reassembly feeds parsed->data directly.
     */
    if (parsed->flags & (EAP_TLS_FLAG_L | EAP_TLS_FLAG_M) || es->tls_len || es->tls_total) {
	/* RFC 5216 2.1.5: L is set on the first fragment of a fragmented
	   TLS message. A first fragment with M but no L is malformed. */
	if (!es->tls_len && !es->tls_total &&
	    (parsed->flags & EAP_TLS_FLAG_M) && !(parsed->flags & EAP_TLS_FLAG_L)) {
	    eap_send_failure(session, es, parsed->identifier);
	    return;
	}
	if (parsed->flags & EAP_TLS_FLAG_L) {
	    uint32_t total;

	    if (es->tls_len || es->tls_total) {
		/* L on a non-first fragment. */
		eap_send_failure(session, es, parsed->identifier);
		return;
	    }
	    if (parsed->data_len < sizeof(total)) {
		eap_send_failure(session, es, parsed->identifier);
		return;
	    }
	    memcpy(&total, parsed->data, sizeof(total));
	    total = ntohl(total);
	    if (total < 1 || total > (uint32_t) r->eap_max_message) {
		eap_send_failure(session, es, parsed->identifier);
		return;
	    }
	    es->tls_total = (size_t) total;
	    tls_data = parsed->data + sizeof(total);
	    tls_data_len = parsed->data_len - sizeof(total);
	}

	if (!eap_tls_append(es, tls_data, tls_data_len, (size_t) r->eap_max_message)) {
	    /* The fragment would exceed eap_max_message. */
	    eap_send_failure(session, es, parsed->identifier);
	    return;
	}

	if (parsed->flags & EAP_TLS_FLAG_M) {
	    /* Fragment ACK: empty EAP-Request/EAP-TLS, incremented identifier. */
	    eap_send_request(session, es, EAP_TYPE_TLS, 0, NULL, 0, 1);
	    return;
	}

	if (es->tls_total && es->tls_len != es->tls_total) {
	    /* Reassembled length does not match the announced total. */
	    eap_send_failure(session, es, parsed->identifier);
	    return;
	}

	tls_data = es->tls_in;
	tls_data_len = es->tls_len;
	reassembled = 1;
    }

    if (!eap_tls_start(es, r)) {
	eap_send_failure(session, es, parsed->identifier);
	return;
    }

    if (BIO_write(es->rbio, tls_data, (int) tls_data_len) != (int) tls_data_len) {
	eap_tls_fail(session, es, "BIO_write");
	if (reassembled) {
	    es->tls_len = 0;
	    es->tls_total = 0;
	}
	return;
    }

    if (reassembled) {
	es->tls_len = 0;
	es->tls_total = 0;
    }

    ret = SSL_do_handshake(es->ssl);
    if (ret == 1) {
	es->flags |= EAP_F_HANDSHAKE_DONE;
	if (r->eap_verify_client && SSL_get_verify_result(es->ssl) != X509_V_OK) {
	    eap_tls_fail(session, es, "client certificate verification");
	    return;
	}
	if (!eap_derive_keys(session, es))
	    return;
    } else {
	err = SSL_get_error(es->ssl, ret);
	if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
	    eap_tls_fail(session, es, "SSL_do_handshake");
	    return;
	}
    }

    if (!eap_tls_drain(es, &buf, &len)) {
	eap_tls_fail(session, es, "BIO_read");
	return;
    }

    if (!len) {
	free(buf);
	if (ret == 1) {
	    /* Defensive: the handshake completed with no server output left
	       to send, so there is no final flight to ACK. */
	    es->tls_state = EAP_TLS_DONE;
	    es->flags |= EAP_F_COMPLETED;
	    es->success_identifier = parsed->identifier;
	    eap_identity_authorize(session, es, parsed->identifier);
	}
	/* Otherwise: waiting for more client data. Never send an empty
	   EAP-Request. */
	return;
    }

    if (!eap_tls_queue(es, buf, len)) {
	free(buf);
	eap_tls_fail(session, es, "BIO_read");
	return;
    }
    free(buf);

    if (ret == 1) {
	/* Final TLS flight (CCS/Finished): fragment it and wait for the
	   peer's fragment ACKs and final empty ACK before EAP-Success. */
	es->tls_state = EAP_TLS_FINAL_FLIGHT_SENDING;
    } else
	es->tls_state = EAP_TLS_HANDSHAKE;

    if (eap_tls_send_fragment(session, es) < 0)
	return;
    if (ret == 1 && es->out_offset >= es->out_total)
	es->tls_state = EAP_TLS_WAIT_FINAL_ACK;
}

void eap_radius_request(tac_session *session)
{
    tac_realm *r = session->ctx->realm;
    struct eap_parsed parsed;
    struct eap_cached_reply *cached;
    struct eap_session *es;
    const u_char *state;
    u_char *eap;
    size_t eap_len, state_len;
    u_char identifier;

    if (session->ctx->radius_1_1 == BISTATE_YES) {
	eap_send_failure(session, NULL, 0);
	return;
    }

    if (!eap_collect(session, &eap, &eap_len) ||
	!eap_get_state(session, &state, &state_len)) {
	eap_send_failure(session, NULL, eap_len >= 2 ? eap[1] : 0);
	return;
    }

    /* A zero-length EAP-Message value is EAP-Start; it must not carry State. */
    if (!eap_len) {
	if (state_len) {
	    eap_send_failure(session, NULL, 0);
	    return;
	}
	es = eap_new_session(r);
	if (!es) {
	    eap_send_failure(session, NULL, 0);
	    return;
	}
	eap_send_request(session, es, EAP_TYPE_IDENTITY, 0, NULL, 0, 0);
	return;
    }

    if (!eap_parse_hdr(eap, eap_len, &parsed)) {
	eap_send_failure(session, NULL, eap_len >= 2 ? eap[1] : 0);
	return;
    }
    identifier = parsed.identifier;

    /* EAP is client-to-server here; anything else is RADIUS role reversal.
       Do not cache the Nak under the offending identifier: a later
       legitimate request could replay it. */
    if (parsed.code != EAP_CODE_RESPONSE) {
	eap_send_nak(session, NULL, identifier);
	return;
    }

    if (!state_len) {
	switch (parsed.type) {
	case EAP_TYPE_IDENTITY:
	    es = eap_new_session(r);
	    if (!es) {
		eap_send_failure(session, NULL, identifier);
		return;
	    }
	    if (!eap_store_identity(es, &parsed)) {
		eap_drop_session(r, es);
		eap_send_failure(session, NULL, identifier);
		return;
	    }
	    es->client_identifier = identifier;
	    es->success_identifier = identifier;
	    es->flags |= EAP_F_IDENTITY_SEEN;
	    eap_send_request(session, es, EAP_TYPE_TLS, EAP_TLS_FLAG_S, NULL, 0, 0);
	    return;
	case EAP_TYPE_NAK:
	    if (!eap_nak_proposes_tls(&parsed)) {
		eap_send_failure(session, NULL, identifier);
		return;
	    }
	    es = eap_new_session(r);
	    if (!es) {
		eap_send_failure(session, NULL, identifier);
		return;
	    }
	    es->client_identifier = identifier;
	    es->success_identifier = identifier;
	    eap_send_request(session, es, EAP_TYPE_TLS, EAP_TLS_FLAG_S, NULL, 0, 0);
	    return;
	default:
	    eap_send_failure(session, NULL, identifier);
	    return;
	}
    }

    es = eap_lookup(r, state, state_len);
    if (!es || es->expires < io_now.tv_sec) {
	/* Unknown or expired State: reject instead of refreshing an expired
	   session. The periodic handler may not have purged it yet. */
	if (es)
	    eap_drop_session(r, es);
	eap_send_failure(session, NULL, identifier);
	return;
    }

    /*
     * RFC 5216 2.1.5: retransmitted fragments keep the same Identifier.
     * Replay the cached reply before dispatching, so neither a retransmitted
     * Access-Request nor a retransmitted final ACK after EAP-Success moves
     * the state machine forward.
     */
    cached = eap_reply_lookup(es, identifier);
    if (cached) {
	/* A valid retransmission: refresh activity and clear the invalid
	   counter without advancing the state machine. */
	es->invalid = 0;
	es->expires = io_now.tv_sec + r->eap_timeout;
	es->last_activity = io_now.tv_sec;
	/* Replay the profile/authorization AVPs from the original reply. */
	if (es->profile_attrs_len && es->profile_attrs) {
	    struct radius_data *rd = session->radius_data;

	    if (rd->data_len + es->profile_attrs_len + RADIUS_HDR_SIZE + 18 <= sizeof(rd->data)) {
		memcpy(rd->data + rd->data_len, es->profile_attrs, es->profile_attrs_len);
		rd->data_len += es->profile_attrs_len;
	    }
	}
#ifdef WITH_CRYPTO
	/* The reply cache holds EAP/State only; the MSK is retained in the
	   completed eap_session and must be re-encrypted with the new
	   Request Authenticator (RFC 2548 2.4.2). */
	if (cached->code == RADIUS_CODE_ACCESS_ACCEPT)
	    eap_add_mppe(session, es);
#endif
	rad_send_eap_reply(session, cached->code, cached->eap, cached->eap_len,
			   cached->state, cached->state_len);
	return;
    }

    if (identifier != es->identifier) {
	es->invalid++;
	if (es->invalid >= EAP_INVALID_LIMIT)
	    report(session, LOG_WARNING, ~0,
		   "EAP: invalid identifier limit reached (%d)", es->invalid);
	/* Every Access-Request needs a reply, but do not cache a failure under
	   an identifier that is not part of the conversation. */
	eap_send_failure(session, NULL, identifier);
	return;
    }

    es->invalid = 0;
    es->client_identifier = identifier;
    es->success_identifier = identifier;
    es->expires = io_now.tv_sec + r->eap_timeout;
    es->last_activity = io_now.tv_sec;

    switch (parsed.type) {
    case EAP_TYPE_IDENTITY:
	/* Identity is only valid without State. */
	eap_send_failure(session, es, identifier);
	return;
    case EAP_TYPE_TLS:
	eap_tls_request(session, es, &parsed);
	return;
    case EAP_TYPE_NAK:
	if (eap_nak_proposes_tls(&parsed))
	    eap_send_request(session, es, EAP_TYPE_TLS, EAP_TLS_FLAG_S, NULL, 0, 1);
	else
	    eap_send_failure(session, es, identifier);
	return;
    default:
	eap_send_failure(session, es, identifier);
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
    free(e->profile_attrs);
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
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());

    if (!ctx)
	goto fail;

    /* TLS 1.2 only: TLS 1.0/1.1 are deprecated by RFC 8996 and disabled by
       modern OpenSSL security levels. This is a deliberate deviation from
       RFC 5216's TLS 1.0/3DES requirements. */
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);

    /* Deterministic server flight: no session tickets (the session cache
       switch does not disable TLS 1.2 tickets), no renegotiation, and no
       compression (RFC 5216 2.4). */
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET | SSL_OP_NO_RENEGOTIATION |
			     SSL_OP_NO_COMPRESSION);

    /* Require the clientAuth EKU on peer certificates. */
    SSL_CTX_set_purpose(ctx, X509_PURPOSE_SSL_CLIENT);

    if (r->eap_pass) {
	SSL_CTX_set_default_passwd_cb(ctx, ssl_pem_phrase_cb);
	SSL_CTX_set_default_passwd_cb_userdata(ctx, r->eap_pass);
    }

    if (!r->eap_cert || !SSL_CTX_use_certificate_chain_file(ctx, r->eap_cert))
	goto fail;
    if (!r->eap_key || !SSL_CTX_use_PrivateKey_file(ctx, r->eap_key, SSL_FILETYPE_PEM))
	goto fail;
    if (!SSL_CTX_check_private_key(ctx))
	goto fail;
    if (r->eap_cafile && !SSL_CTX_load_verify_locations(ctx, r->eap_cafile, NULL))
	goto fail;

    if (r->eap_verify_client)
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    else
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    return ctx;

fail:
    {
	char ebuf[256];
	const char *terr = ERR_error_string(ERR_get_error(), ebuf);

	report(NULL, LOG_ERR, ~0,
	       "%s %d: realm %s: EAP TLS configuration failed%s%s",
	       __func__, __LINE__, r->name.txt, terr ? ": " : "", terr ? terr : "");
    }
    SSL_CTX_free(ctx);
    return NULL;
}

#endif				/* WITH_SSL */

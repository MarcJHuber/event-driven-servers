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

#ifndef __EAP_H_
#define __EAP_H_

#include <openssl/ssl.h>
#include "misc/str.h"

#define EAP_CODE_REQUEST    1
#define EAP_CODE_RESPONSE   2
#define EAP_CODE_SUCCESS    3
#define EAP_CODE_FAILURE    4

#define EAP_TYPE_IDENTITY   1
#define EAP_TYPE_NOTIFICATION 2
#define EAP_TYPE_NAK        3
#define EAP_TYPE_TLS        13

#define EAP_TLS_FLAG_L      0x80
#define EAP_TLS_FLAG_M      0x40
#define EAP_TLS_FLAG_S      0x20
#define EAP_TLS_FLAG_RESERVED 0x1f	/* Request; Response reserved is 0x3f */

#define EAP_STATE_LEN       16
#define EAP_INVALID_LIMIT   5
#define EAP_DEFAULT_TIMEOUT 60
#define EAP_DEFAULT_MAX_MESSAGE 65535
#define EAP_DEFAULT_MAX_SESSIONS 4096
#define EAP_MAX_RADIUS_ATTR 253
#define EAP_MAX_FRAGMENT    3000
#define EAP_REPLY_CACHE_SIZE 4
#define EAP_COMPLETED_GRACE 30

enum eap_tls_state {
    EAP_TLS_NONE = 0,
    EAP_TLS_HANDSHAKE,
    EAP_TLS_FINAL_FLIGHT_SENDING,
    EAP_TLS_WAIT_FINAL_ACK,
    EAP_TLS_ALERT_SENT,
    EAP_TLS_DONE,
};

struct eap_hdr {
    u_char code;
    u_char identifier;
    u_short length;
} __attribute__((__packed__));

struct eap_fragment {
    struct eap_fragment *next;
    size_t len;
    u_char data[1];
};

struct eap_cached_reply {
    u_char identifier;
    u_char code;
    u_char *eap;
    size_t eap_len;
    u_char *state;
    size_t state_len;
};

struct eap_session {
    u_char state[EAP_STATE_LEN];
    size_t state_len;
    tac_host *host;		/* RADIUS client this session belongs to */
    struct in6_addr peer_addr;	/* client address, host byte order */
    enum token transport;	/* S_radius_udp, S_radius_tcp, S_radius_tls, S_radius_dtls */
    time_t expires;
    time_t last_activity;
    u_char identifier;		/* last EAP identifier sent */
    u_char client_identifier;	/* last client EAP identifier seen */
    u_char success_identifier;	/* identifier for EAP-Success/Failure */
    int invalid;		/* invalid packets seen */
    int flags;
#define EAP_F_IDENTITY_SEEN 0x01
#define EAP_F_TLS_STARTED   0x02
#define EAP_F_HANDSHAKE_DONE 0x04
#define EAP_F_FAILED        0x08
#define EAP_F_FRAGMENT_ACK  0x10
#define EAP_F_COMPLETED     0x20
#define EAP_F_ALERT_SENT    0x40

    enum eap_tls_state tls_state;
    str_t identity;		/* EAP-Response/Identity, unauthenticated */
    SSL *ssl;
    BIO *rbio;
    BIO *wbio;

    u_char *in;			/* EAP-Message reassembly buffer */
    size_t in_len;
    size_t in_max;

    u_char *tls_in;		/* EAP-TLS fragment reassembly buffer */
    size_t tls_len;
    size_t tls_max;
    size_t tls_total;		/* announced total, if L was set */

    struct eap_fragment *out;	/* pending EAP-TLS fragments */
    size_t out_offset;		/* offset of the next fragment */
    size_t out_total;

    struct eap_cached_reply reply_cache[EAP_REPLY_CACHE_SIZE];
    int reply_cache_next;

    u_char *profile_attrs;	/* profile/authorization AVPs for replay */
    size_t profile_attrs_len;

    u_char msk[64];
    u_char emsk[64];
};

int eap_has_message(rad_pak_hdr *pak);
void eap_radius_request(tac_session *session);
void eap_expire_sessions(tac_realm *r);
void eap_session_free(void *payload);
int eap_session_cmp(const void *a, const void *b);
SSL_CTX *eap_ssl_init(tac_realm *r);

#endif				/* __EAP_H_ */

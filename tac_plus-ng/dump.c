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

static const char rcsid[] __attribute__((used)) = "$Id$";

struct i2s {
    int key;
    str_t str;
};

#define I2S(A,B) { A, { B, sizeof(B) - 1 } }

static struct i2s map_authen_type[] = {
    I2S(0, "AUTHEN/UNKNOWN"),
    I2S(TAC_PLUS_AUTHEN_STATUS_PASS, "AUTHEN/PASS"),
    I2S(TAC_PLUS_AUTHEN_STATUS_FAIL, "AUTHEN/FAIL"),
    I2S(TAC_PLUS_AUTHEN_STATUS_GETDATA, "AUTHEN/GETDATA"),
    I2S(TAC_PLUS_AUTHEN_STATUS_GETUSER, "AUTHEN/GETUSER"),
    I2S(TAC_PLUS_AUTHEN_STATUS_GETPASS, "AUTHEN/GETPASS"),
    I2S(TAC_PLUS_AUTHEN_STATUS_ERROR, "AUTHEN/ERROR"),
    I2S(TAC_PLUS_AUTHEN_STATUS_FOLLOW, "AUTHEN/FOLLOW"),
    { 0 }
};

static struct i2s map_author_type[] = {
    I2S(0, "AUTHOR/UNKNOWN"),
    I2S(TAC_PLUS_AUTHOR_STATUS_PASS_ADD, "AUTHOR/PASS_ADD"),
    I2S(TAC_PLUS_AUTHOR_STATUS_FAIL, "AUTHOR/FAIL"),
    I2S(TAC_PLUS_AUTHOR_STATUS_PASS_REPL, "AUTHOR/PASS_REPL"),
    I2S(TAC_PLUS_AUTHOR_STATUS_ERROR, "AUTHOR/ERROR"),
    { 0 }
};

static struct i2s map_acct_type[] = {
    I2S(0, "ACCT/UNKNOWN"),
    I2S(TAC_PLUS_ACCT_STATUS_SUCCESS, "ACCT/SUCCESS"),
    I2S(TAC_PLUS_ACCT_STATUS_ERROR, "ACCT/ERROR"),
    I2S(TAC_PLUS_ACCT_STATUS_FOLLOW, "ACCT/FOLLOW"),
    { 0 }
};

static struct i2s map_action[] = {
    I2S(0, "unknown"),
    I2S(TAC_PLUS_AUTHEN_LOGIN, "login"),
    I2S(TAC_PLUS_AUTHEN_CHPASS, "chpass"),
    I2S(TAC_PLUS_AUTHEN_SENDPASS, "sendpass"),
    I2S(TAC_PLUS_AUTHEN_SENDAUTH, "sendauth"),
    { 0 }
};

static struct i2s map_type[] = {
    I2S(0, "unknown"),
    I2S(TAC_PLUS_AUTHEN_TYPE_ASCII, "ascii"),
    I2S(TAC_PLUS_AUTHEN_TYPE_PAP, "pap"),
    I2S(TAC_PLUS_AUTHEN_TYPE_CHAP, "chap"),
    I2S(TAC_PLUS_AUTHEN_TYPE_ARAP, "arap"),
    I2S(TAC_PLUS_AUTHEN_TYPE_MSCHAP, "mschap"),
    I2S(TAC_PLUS_AUTHEN_TYPE_MSCHAPV2, "mschapv2"),
    I2S(TAC_PLUS_AUTHEN_TYPE_SSHKEY, "sshkey"),
    I2S(TAC_PLUS_AUTHEN_TYPE_SSHCERT, "sshcert"),
    I2S(TAC_PLUS_AUTHEN_TYPE_EAP, "eap"),
    { 0 }
};

static struct i2s map_service[] = {
    I2S(0, "unknown"),
    I2S(TAC_PLUS_AUTHEN_SVC_LOGIN, "login"),
    I2S(TAC_PLUS_AUTHEN_SVC_ENABLE, "enable"),
    I2S(TAC_PLUS_AUTHEN_SVC_PPP, "ppp"),
    I2S(TAC_PLUS_AUTHEN_SVC_ARAP, "arap"),
    I2S(TAC_PLUS_AUTHEN_SVC_PT, "pt"),
    I2S(TAC_PLUS_AUTHEN_SVC_RCMD, "rcmd"),
    I2S(TAC_PLUS_AUTHEN_SVC_X25, "x25"),
    I2S(TAC_PLUS_AUTHEN_SVC_NASI, "nasi"),
    I2S(TAC_PLUS_AUTHEN_SVC_FWPROXY, "fwproxy"),
    { 0 }
};

static struct i2s map_method[] = {
    I2S(0, "unknown"),
    I2S(TAC_PLUS_AUTHEN_METH_NOT_SET, "not set"),
    I2S(TAC_PLUS_AUTHEN_METH_NONE, "none"),
    I2S(TAC_PLUS_AUTHEN_METH_KRB5, "krb5"),
    I2S(TAC_PLUS_AUTHEN_METH_LINE, "line"),
    I2S(TAC_PLUS_AUTHEN_METH_ENABLE, "enable"),
    I2S(TAC_PLUS_AUTHEN_METH_LOCAL, "local"),
    I2S(TAC_PLUS_AUTHEN_METH_TACACSPLUS, "tacacs+"),
    I2S(TAC_PLUS_AUTHEN_METH_GUEST, "guest"),
    I2S(TAC_PLUS_AUTHEN_METH_RADIUS, "radius"),
    I2S(TAC_PLUS_AUTHEN_METH_KRB4, "krb4"),
    I2S(TAC_PLUS_AUTHEN_METH_RCMD, "rcmd"),
    { 0 }
};

static str_t *i2str(struct i2s *s, int i)
{
    struct i2s *r = s;

    do
	s++;
    while (s->str.txt && i != s->key);

    if (s->str.txt)
	return &s->str;

    return &r->str;
}

static char *i2s(struct i2s *s, int i, size_t *len)
{
    str_t *r = i2str(s, i);
    if (len)
	*len = r->len;
    return r->txt;
}

void get_pkt_data(tac_session *session, struct authen_start *start, struct author *author)
{
    if (start) {
	session->authen_action = i2str(map_action, start->action);
	session->authen_type = i2str(map_type, start->type);
	session->authen_service = i2str(map_service, start->service);
    } else if (author) {
	session->authen_type = i2str(map_type, author->authen_type);
	session->authen_service = i2str(map_service, author->service);
	session->authen_method = i2str(map_method, author->authen_method);
    }
}

char *summarise_outgoing_packet_type(tac_pak_hdr *hdr)
{
    switch (hdr->type) {
    case TAC_PLUS_AUTHEN:
	return i2s(map_authen_type, tac_payload(hdr, struct authen_reply *)->status, NULL);
    case TAC_PLUS_AUTHOR:
	return i2s(map_author_type, tac_payload(hdr, struct author_reply *)->status, NULL);
    case TAC_PLUS_ACCT:
	return i2s(map_acct_type, tac_payload(hdr, struct acct_reply *)->status, NULL);
    default:
	return "UNKNOWN";
    }
}

#define DEBPACK session, LOG_DEBUG, DEBUG_PACKET_FLAG
#define DEBHEX session, LOG_DEBUG, DEBUG_HEX_FLAG

static void dump_header(tac_session *session, tac_pak_hdr *hdr, int bogus)
{
    if (!(common_data.debug & DEBUG_TACTRACE_FLAG)) {
	report(DEBPACK, "key used: %s", session->ctx->key ? session->ctx->key->key : "<NULL>");

	report(DEBPACK, "version: %d, type: %d, seq no: %d, flags: %s%sencrypted%s%s",
	       hdr->version, hdr->type, hdr->seq_no,
	       common_data.font_blue,
	       hdr->flags & TAC_PLUS_UNENCRYPTED_FLAG ? "un" : "", hdr->flags & TAC_PLUS_SINGLE_CONNECT_FLAG ? " single-connect" : "",
	       common_data.font_plain);
    }

    report(DEBPACK, "session id: %.8x, data length: %d", (unsigned int) ntohl(hdr->session_id), (int) ntohl(hdr->datalength));

    if (!bogus && (hdr->seq_no & 1) && !(session->debug & DEBUG_USERINPUT_FLAG) && (hdr->type == TAC_PLUS_AUTHEN)) {
	size_t n = ntohl(hdr->datalength);
	size_t l;
	if (hdr->seq_no == 1) {
	    struct authen_start *start = tac_payload(hdr, struct authen_start *);
	    l = start->data_len;
	} else {
	    struct authen_cont *cont = tac_payload(hdr, struct authen_cont *);
	    l = ntohs(cont->user_msg_len) + ntohs(cont->user_data_len);
	}
	if (l) {
	    char t[n];
	    memcpy(t, tac_payload(hdr, char *), n);
	    memset(t + n - l, '*', l);
	    report(DEBHEX, "%spacket body [partially masked]%s (len: %d):%s", common_data.font_red, common_data.font_plain, (int) l, common_data.font_plain);
	    report_hex(DEBHEX, (u_char *) t, n);
	    return;
	}
    }
    report(DEBHEX, "%spacket body%s (len: %d):%s", common_data.font_red, common_data.font_plain, (int) ntohl(hdr->datalength), common_data.font_plain);
    report_hex(DEBHEX, tac_payload(hdr, u_char *), ntohl(hdr->datalength));
}

static void dump_args(tac_session *session, u_char arg_cnt, char *p, unsigned char *sizep)
{
    for (int i = 0; i < arg_cnt; i++) {
	char a[20];
	snprintf(a, sizeof(a), "arg[%d]", i);
	report_string(DEBPACK, a, p, *sizep);
	p += *sizep;
	sizep++;
    }
}

/* Dump packets originated by a NAS */
void dump_nas_pak(tac_session *session, int bogus)
{
    char *p;
    unsigned char *argsizep;
    tac_pak_hdr *hdr = &session->ctx->in->pak.tac;

    report(DEBPACK, "%s---<start packet>---%s", common_data.font_green, common_data.font_plain);
    dump_header(session, hdr, bogus);

    if (bogus) {
	report(DEBPACK, "Packet malformed, skipping detailed dump.");
    } else {
	switch (hdr->type) {
	case TAC_PLUS_AUTHEN:
	    if (hdr->seq_no == 1) {
		struct authen_start *start = tac_payload(hdr, struct authen_start *);

		report(DEBPACK, "AUTHEN/START, priv_lvl=%d", start->priv_lvl);
		report(DEBPACK, "action=%s (%d)", i2s(map_action, start->action, NULL), start->action);
		report(DEBPACK, "authen_type=%s (%d)", i2s(map_type, start->type, NULL), start->type);
		report(DEBPACK, "service=%s (%d)", i2s(map_service, start->service, NULL), start->service);
		report(DEBPACK, "user_len=%d port_len=%d rem_addr_len=%d", start->user_len, start->port_len, start->rem_addr_len);
		report(DEBPACK, "data_len=%d", start->data_len);
		p = (char *) start + TAC_AUTHEN_START_FIXED_FIELDS_SIZE;
		report_string(DEBPACK, "user", p, start->user_len);
		p += start->user_len;
		report_string(DEBPACK, "port", p, start->port_len);
		p += start->port_len;
		report_string(DEBPACK, "rem_addr", p, start->rem_addr_len);
		if ((session->debug & DEBUG_USERINPUT_FLAG)
		    || (start->type == TAC_PLUS_AUTHEN_TYPE_SSHKEY)	// it's safe to show the key hash
		    || (start->type == TAC_PLUS_AUTHEN_TYPE_SSHCERT)
		    ) {
		    p += start->rem_addr_len;
		    report_string(DEBPACK, "data", p, start->data_len);
		}
	    } else {
		struct authen_cont *cont = tac_payload(hdr, struct authen_cont *);

		report(DEBPACK, "AUTHEN/CONT user_msg_len=%d, user_data_len=%d", ntohs(cont->user_msg_len), ntohs(cont->user_data_len));
		if (session->debug & DEBUG_USERINPUT_FLAG) {
		    p = (char *) cont + TAC_AUTHEN_CONT_FIXED_FIELDS_SIZE;
		    report_string(DEBPACK, "user_msg", p, ntohs(cont->user_msg_len));
		    p += cont->user_msg_len;
		    report_string(DEBPACK, "user_data", p, ntohs(cont->user_data_len));
		}
	    }
	    break;
	case TAC_PLUS_AUTHOR:
	    {
		struct author *author = tac_payload(hdr, struct author *);

		report(DEBPACK, "AUTHOR, priv_lvl=%d", author->priv_lvl);
		report(DEBPACK, "authen_type=%s (%d)", i2s(map_type, author->authen_type, NULL), author->authen_type);
		report(DEBPACK, "authen_method=%s (%d)", i2s(map_method, author->authen_method, NULL), author->authen_method);
		report(DEBPACK, "service=%s (%d)", i2s(map_service, author->service, NULL), author->service);
		report(DEBPACK,
		       "user_len=%d port_len=%d rem_addr_len=%d arg_cnt=%d", author->user_len, author->port_len, author->rem_addr_len, author->arg_cnt);

		p = (char *) author + TAC_AUTHOR_REQ_FIXED_FIELDS_SIZE;
		argsizep = (unsigned char *) p;
		p += author->arg_cnt;
		report_string(DEBPACK, "user", p, author->user_len);
		p += author->user_len;
		report_string(DEBPACK, "port", p, author->port_len);
		p += author->port_len;
		report_string(DEBPACK, "rem_addr", p, author->rem_addr_len);
		p += author->rem_addr_len;
		dump_args(session, author->arg_cnt, p, argsizep);
	    }
	    break;
	case TAC_PLUS_ACCT:
	    {
		struct acct *acct = tac_payload(hdr, struct acct *);

		report(DEBPACK, "ACCT, priv_lvl=%d flags=0x%x", acct->priv_lvl, acct->flags);
		report(DEBPACK, "authen_type=%s (%d)", i2s(map_type, acct->authen_type, NULL), acct->authen_type);
		report(DEBPACK, "authen_method=%s (%d)", i2s(map_method, acct->authen_method, NULL), acct->authen_method);
		report(DEBPACK, "service=%s (%d)", i2s(map_service, acct->authen_service, NULL), acct->authen_service);
		report(DEBPACK, "user_len=%d port_len=%d rem_addr_len=%d arg_cnt=%d", acct->user_len, acct->port_len, acct->rem_addr_len, acct->arg_cnt);

		p = (char *) acct + TAC_ACCT_REQ_FIXED_FIELDS_SIZE;
		argsizep = (unsigned char *) p;
		p += acct->arg_cnt;
		report_string(DEBPACK, "user", p, acct->user_len);
		p += acct->user_len;
		report_string(DEBPACK, "port", p, acct->port_len);
		p += acct->port_len;
		report_string(DEBPACK, "rem_addr", p, acct->rem_addr_len);
		p += acct->rem_addr_len;
		dump_args(session, acct->arg_cnt, p, argsizep);
	    }
	    break;
	default:
	    report(DEBPACK, "%s: unrecognized header type %d", __func__, hdr->type);
	}
    }
    report(DEBPACK, "%s---<end packet>---%s", common_data.font_green, common_data.font_plain);
}

/* Dump packets originated by tac_plus */
void dump_tacacs_pak(tac_session *session, tac_pak_hdr *hdr)
{
    char *p;

    report(DEBPACK, "%s---<start packet>---%s", common_data.font_green, common_data.font_plain);
    dump_header(session, hdr, 0);

    switch (hdr->type) {
    case TAC_PLUS_AUTHEN:
	{
	    struct authen_reply *authen = tac_payload(hdr, struct authen_reply *);

	    report(DEBPACK, "AUTHEN, status=%d (%s) flags=0x%x", authen->status, summarise_outgoing_packet_type(hdr), authen->flags);
	    report(DEBPACK, "msg_len=%d, data_len=%d", ntohs(authen->msg_len), ntohs(authen->data_len));
	    /* start of variable length data is here */
	    p = (char *) authen + TAC_AUTHEN_REPLY_FIXED_FIELDS_SIZE;
	    report_string(DEBPACK, "msg", p, ntohs(authen->msg_len));
	    p += ntohs(authen->msg_len);
	    report_string(DEBPACK, "data", p, ntohs(authen->data_len));
	}
	break;
    case TAC_PLUS_AUTHOR:
	{
	    struct author_reply *author = tac_payload(hdr, struct author_reply *);
	    unsigned char *argsizep;

	    report(DEBPACK, "AUTHOR/REPLY, status=%d (%s) ", author->status, summarise_outgoing_packet_type(hdr));
	    report(DEBPACK, "msg_len=%d, data_len=%d, arg_cnt=%d", ntohs(author->msg_len), ntohs(author->data_len), author->arg_cnt);
	    p = (char *) author + TAC_AUTHOR_REPLY_FIXED_FIELDS_SIZE;
	    argsizep = (unsigned char *) p;
	    p += author->arg_cnt;
	    report_string(DEBPACK, "msg", p, ntohs(author->msg_len));
	    p += ntohs(author->msg_len);
	    report_string(DEBPACK, "data", p, ntohs(author->data_len));
	    p += ntohs(author->data_len);
	    dump_args(session, author->arg_cnt, p, argsizep);
	}
	break;
    case TAC_PLUS_ACCT:
	{
	    struct acct_reply *acct = tac_payload(hdr, struct acct_reply *);

	    report(DEBPACK, "ACCT/REPLY, status=%d (%s), msg_len=%d, data_len=%d", acct->status, summarise_outgoing_packet_type(hdr), ntohs(acct->msg_len),
		   ntohs(acct->data_len));
	    p = (char *) acct + TAC_ACCT_REPLY_FIXED_FIELDS_SIZE;
	    report_string(DEBPACK, "msg", p, ntohs(acct->msg_len));
	    p += ntohs(acct->msg_len);
	    report_string(DEBPACK, "data", p, ntohs(acct->data_len));
	}
	break;
    default:
	report(DEBPACK, "%s: unrecognized header type %d", __func__, hdr->type);
    }
    report(DEBPACK, "%s---<end packet>---%s", common_data.font_green, common_data.font_plain);
}

static struct i2s map_rad_code[] = {
    I2S(0, "unknown"),
    I2S(RADIUS_CODE_ACCESS_REQUEST, "ACCESS-REQUEST"),
    I2S(RADIUS_CODE_ACCESS_ACCEPT, "ACCESS-ACCEPT"),
    I2S(RADIUS_CODE_ACCESS_REJECT, "ACCESS-REJECT"),
    I2S(RADIUS_CODE_ACCESS_CHALLENGE, "ACCESS-CHALLENGE"),
    I2S(RADIUS_CODE_ACCOUNTING_REQUEST, "ACCOUNTING-REQUEST"),
    I2S(RADIUS_CODE_ACCOUNTING_RESPONSE, "ACCOUNTING-RESPONSE"),
    I2S(RADIUS_CODE_STATUS_SERVER, "STATUS-SERVER"),
    I2S(RADIUS_CODE_STATUS_CLIENT, "STATUS-CLIENT"),
    I2S(RADIUS_CODE_PROTOCOL_ERROR, "PROTOCOL-ERROR"),
    { 0 }
};

static void rad_sanitize_pak(u_char *out, u_char *in, size_t len)
{
    memcpy(out, in, RADIUS_HDR_SIZE);
    in += RADIUS_HDR_SIZE;
    out += RADIUS_HDR_SIZE;
    len -= RADIUS_HDR_SIZE;
    for (u_char * end = in + len; in < end;) {
	int hide = (*in == RADIUS_A_USER_PASSWORD);
	*out = *in;
	out++, in++;
	*out = *in;
	u_char fl = *in - 2;
	out++, in++;
	for (; fl; fl--) {
	    *out = hide ? '*' : *in;
	    out++, in++;
	}
    }
}

void dump_rad_pak(tac_session *session, rad_pak_hdr *pkt)
{
    if (!(common_data.debug & DEBUG_TACTRACE_FLAG) && !session->ctx->radius_1_1)
	report(DEBPACK, "key used: %s", session->ctx->key ? session->ctx->key->key : "<NULL>");

    report(DEBPACK, "%s---<start packet>---%s", common_data.font_green, common_data.font_plain);
    report(DEBHEX, "%spacket%s (len: %d):%s", common_data.font_red, common_data.font_plain, (int) ntohs(pkt->length), common_data.font_plain);

    {
	size_t pkt_len = ntohs(pkt->length);
	u_char p[pkt_len];
	rad_sanitize_pak(p, (u_char *) pkt, pkt_len);
	report_hex(DEBHEX, p, pkt_len);
    }

    report(DEBPACK, "%scode=%s [%u] identifer=%u length=%u%s", common_data.font_blue, i2s(map_rad_code, pkt->code, NULL),
	   pkt->code, pkt->identifier, ntohs(pkt->length), common_data.font_plain);

    char *buf = NULL;
    size_t buf_len = 0;
    rad_attr_val_dump(session->mem, RADIUS_DATA(pkt), RADIUS_DATA_LEN(pkt), &buf, &buf_len, NULL, "\n\t", 2);

    if (*buf)
	report(DEBPACK, "Attributes: \n\t%s%s%s", common_data.font_red, buf, common_data.font_plain);
    else
	report(DEBPACK, "Attributes: None");

    report(DEBPACK, "%s---<end packet>---%s", common_data.font_green, common_data.font_plain);
}

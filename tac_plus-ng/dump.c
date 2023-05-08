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
    char *str;
    size_t str_len;
};

static struct i2s map_authen_type[] = {
    { 0, "AUTHEN/UNKNOWN", 0 },
    { TAC_PLUS_AUTHEN_STATUS_PASS, "AUTHEN/PASS", 0 },
    { TAC_PLUS_AUTHEN_STATUS_FAIL, "AUTHEN/FAIL", 0 },
    { TAC_PLUS_AUTHEN_STATUS_GETDATA, "AUTHEN/GETDATA", 0 },
    { TAC_PLUS_AUTHEN_STATUS_GETUSER, "AUTHEN/GETUSER", 0 },
    { TAC_PLUS_AUTHEN_STATUS_GETPASS, "AUTHEN/GETPASS", 0 },
    { TAC_PLUS_AUTHEN_STATUS_ERROR, "AUTHEN/ERROR", 0 },
    { TAC_PLUS_AUTHEN_STATUS_FOLLOW, "AUTHEN/FOLLOW", 0 },
    { 0, NULL, 0 }
};

static struct i2s map_author_type[] = {
    { 0, "AUTHOR/UNKNOWN", 0 },
    { TAC_PLUS_AUTHOR_STATUS_PASS_ADD, "AUTHOR/PASS_ADD", 0 },
    { TAC_PLUS_AUTHOR_STATUS_FAIL, "AUTHOR/FAIL", 0 },
    { TAC_PLUS_AUTHOR_STATUS_PASS_REPL, "AUTHOR/PASS_REPL", 0 },
    { TAC_PLUS_AUTHOR_STATUS_ERROR, "AUTHOR/ERROR", 0 },
    { 0, NULL, 0 }
};

static struct i2s map_action[] = {
    { 0, "unknown", 0 },
    { TAC_PLUS_AUTHEN_LOGIN, "login", 0 },
    { TAC_PLUS_AUTHEN_CHPASS, "chpass", 0 },
    { TAC_PLUS_AUTHEN_SENDPASS, "sendpass", 0 },
    { TAC_PLUS_AUTHEN_SENDAUTH, "sendauth", 0 },
    { 0, NULL, 0 }
};

static struct i2s map_type[] = {
    { 0, "unknown", 0 },
    { TAC_PLUS_AUTHEN_TYPE_ASCII, "ascii", 0 },
    { TAC_PLUS_AUTHEN_TYPE_PAP, "pap", 0 },
    { TAC_PLUS_AUTHEN_TYPE_CHAP, "chap", 0 },
    { TAC_PLUS_AUTHEN_TYPE_ARAP, "arap", 0 },
    { TAC_PLUS_AUTHEN_TYPE_MSCHAP, "mschap", 0 },
    { TAC_PLUS_AUTHEN_TYPE_MSCHAPV2, "mschapv2", 0 },
    { TAC_PLUS_AUTHEN_TYPE_SSHKEY, "sshkey", 0 },
    { TAC_PLUS_AUTHEN_TYPE_SSHCERT, "sshcert", 0 },
    { 0, NULL, 0 }
};

static struct i2s map_service[] = {
    { 0, "unknown", 0 },
    { TAC_PLUS_AUTHEN_SVC_LOGIN, "login", 0 },
    { TAC_PLUS_AUTHEN_SVC_ENABLE, "enable", 0 },
    { TAC_PLUS_AUTHEN_SVC_PPP, "ppp", 0 },
    { TAC_PLUS_AUTHEN_SVC_ARAP, "arap", 0 },
    { TAC_PLUS_AUTHEN_SVC_PT, "pt", 0 },
    { TAC_PLUS_AUTHEN_SVC_RCMD, "rcmd", 0 },
    { TAC_PLUS_AUTHEN_SVC_X25, "x25", 0 },
    { TAC_PLUS_AUTHEN_SVC_NASI, "nasi", 0 },
    { 0, NULL, 0 }
};

static struct i2s map_method[] = {
    { 0, "unknown", 0 },
    { TAC_PLUS_AUTHEN_METH_NOT_SET, "not set", 0 },
    { TAC_PLUS_AUTHEN_METH_NONE, "none", 0 },
    { TAC_PLUS_AUTHEN_METH_KRB5, "krb5", 0 },
    { TAC_PLUS_AUTHEN_METH_LINE, "line", 0 },
    { TAC_PLUS_AUTHEN_METH_ENABLE, "enable", 0 },
    { TAC_PLUS_AUTHEN_METH_LOCAL, "local", 0 },
    { TAC_PLUS_AUTHEN_METH_TACACSPLUS, "tacacs+", 0 },
    { TAC_PLUS_AUTHEN_METH_GUEST, "guest", 0 },
    { TAC_PLUS_AUTHEN_METH_RADIUS, "radius", 0 },
    { TAC_PLUS_AUTHEN_METH_KRB4, "krb4", 0 },
    { TAC_PLUS_AUTHEN_METH_RCMD, "rcmd", 0 },
    { 0, NULL, 0 }
};

static char *i2s(struct i2s *s, int i, size_t *len)
{
    struct i2s *r = s;

    do
	s++;
    while (s->str && i != s->key);

    if (!s->str)
	s = r;

    if (s->str && !s->str_len)
	s->str_len = strlen(s->str);

    if (len)
	*len = s->str_len;

    return s->str;
}

void get_pkt_data(tac_session * session, struct authen_start *start, struct author *author)
{
    if (start) {
	session->authen_action = i2s(map_action, start->action, &session->authen_action_len);
	session->authen_type = i2s(map_authen_type, start->type, &session->authen_type_len);
	session->authen_service = i2s(map_service, start->service, &session->authen_service_len);
    } else if (author) {
	session->authen_type = i2s(map_authen_type, author->authen_type, &session->authen_type_len);
	session->authen_service = i2s(map_service, author->service, &session->authen_service_len);
	session->authen_method = i2s(map_method, author->authen_method, &session->authen_method_len);
    }
}

char *summarise_outgoing_packet_type(tac_pak_hdr * hdr)
{
    switch (hdr->type) {
    case TAC_PLUS_AUTHEN:
	return i2s(map_authen_type, tac_payload(hdr, struct authen_reply *)->status, NULL);
    case TAC_PLUS_AUTHOR:
	return i2s(map_author_type, tac_payload(hdr, struct author_reply *)->status, NULL);
    case TAC_PLUS_ACCT:
	return "ACCT";
    default:
	return "UNKNOWN";
    }
}

static void dump_header(tac_session * session, tac_pak_hdr * hdr, int bogus)
{
    if (!(common_data.debug & DEBUG_TACTRACE_FLAG)) {
	report(session, LOG_DEBUG, DEBUG_PACKET_FLAG, "key used: %s", session->ctx->key ? session->ctx->key->key : "<NULL>");

	report(session, LOG_DEBUG, DEBUG_PACKET_FLAG,
	       "version: %d, type: %d, seq no: %d, flags: %s%sencrypted%s%s",
	       hdr->version, hdr->type, hdr->seq_no,
	       common_data.font_blue,
	       hdr->flags & TAC_PLUS_UNENCRYPTED_FLAG ? "un" : "", hdr->flags & TAC_PLUS_SINGLE_CONNECT_FLAG ? " single-connect" : "",
	       common_data.font_plain);
    }

    report(session, LOG_DEBUG, DEBUG_PACKET_FLAG, "session id: %.8x, data length: %d", (unsigned int) ntohl(hdr->session_id), (int) ntohl(hdr->datalength));

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
	    char *t = alloca(n);
	    if (t) {
		memcpy(t, tac_payload(hdr, char *), n);
		memset(t + n - l, '*', l);
		report_string(session, LOG_DEBUG, DEBUG_HEX_FLAG, "packet body [partially masked]", t, n);
		return;
	    }
	}
    }
    report_string(session, LOG_DEBUG, DEBUG_HEX_FLAG, "packet body", tac_payload(hdr, char *), ntohl(hdr->datalength));
}

static void dump_args(tac_session * session, u_char arg_cnt, char *p, unsigned char *sizep)
{
    int i;

    for (i = 0; i < arg_cnt; i++) {
	char a[20];
	snprintf(a, sizeof(a), "arg[%d]", i);
	report_string(session, LOG_DEBUG, DEBUG_PACKET_FLAG, a, p, *sizep);
	p += *sizep;
	sizep++;
    }
}

/* Dump packets originated by a NAS */
void dump_nas_pak(tac_session * session, int bogus)
{
    char *p;
    unsigned char *argsizep;
    tac_pak_hdr *hdr = &session->ctx->in->hdr;

    report(session, LOG_DEBUG, DEBUG_PACKET_FLAG, "%s---<start packet>---%s", common_data.font_green, common_data.font_plain);
    dump_header(session, hdr, bogus);

    if (bogus) {
	report(session, LOG_DEBUG, DEBUG_PACKET_FLAG, "Packet malformed, skipping detailed dump.");
    } else {
	switch (hdr->type) {
	case TAC_PLUS_AUTHEN:
	    if (hdr->seq_no == 1) {
		struct authen_start *start = tac_payload(hdr, struct authen_start *);

		report(session, LOG_DEBUG, DEBUG_PACKET_FLAG, "AUTHEN/START, priv_lvl=%d", start->priv_lvl);
		report(session, LOG_DEBUG, DEBUG_PACKET_FLAG, "action=%s (%d)", i2s(map_action, start->action, NULL), start->action);
		report(session, LOG_DEBUG, DEBUG_PACKET_FLAG, "authen_type=%s (%d)", i2s(map_type, start->type, NULL), start->type);
		report(session, LOG_DEBUG, DEBUG_PACKET_FLAG, "service=%s (%d)", i2s(map_service, start->service, NULL), start->service);
		report(session, LOG_DEBUG, DEBUG_PACKET_FLAG,
		       "user_len=%d port_len=%d rem_addr_len=%d", start->user_len, start->port_len, start->rem_addr_len);
		report(session, LOG_DEBUG, DEBUG_PACKET_FLAG, "data_len=%d", start->data_len);
		p = (char *) start + TAC_AUTHEN_START_FIXED_FIELDS_SIZE;
		report_string(session, LOG_DEBUG, DEBUG_PACKET_FLAG, "user", p, start->user_len);
		p += start->user_len;
		report_string(session, LOG_DEBUG, DEBUG_PACKET_FLAG, "port", p, start->port_len);
		p += start->port_len;
		report_string(session, LOG_DEBUG, DEBUG_PACKET_FLAG, "rem_addr", p, start->rem_addr_len);
		if ((session->debug & DEBUG_USERINPUT_FLAG)
		    || (start->type == TAC_PLUS_AUTHEN_TYPE_SSHKEY)	// it's safe to show the key hash
		    || (start->type == TAC_PLUS_AUTHEN_TYPE_SSHCERT)
		    ) {
		    p += start->rem_addr_len;
		    report_string(session, LOG_DEBUG, DEBUG_PACKET_FLAG, "data", p, start->data_len);
		}
	    } else {
		struct authen_cont *cont = tac_payload(hdr, struct authen_cont *);

		report(session, LOG_DEBUG, DEBUG_PACKET_FLAG,
		       "AUTHEN/CONT user_msg_len=%d, user_data_len=%d", ntohs(cont->user_msg_len), ntohs(cont->user_data_len));
		if (session->debug & DEBUG_USERINPUT_FLAG) {
		    p = (char *) cont + TAC_AUTHEN_CONT_FIXED_FIELDS_SIZE;
		    report_string(session, LOG_DEBUG, DEBUG_PACKET_FLAG, "user_msg", p, ntohs(cont->user_msg_len));
		    p += cont->user_msg_len;
		    report_string(session, LOG_DEBUG, DEBUG_PACKET_FLAG, "user_data", p, ntohs(cont->user_data_len));
		}
	    }
	    break;
	case TAC_PLUS_AUTHOR:
	    {
		struct author *author = tac_payload(hdr, struct author *);

		report(session, LOG_DEBUG, DEBUG_PACKET_FLAG, "AUTHOR, priv_lvl=%d", author->priv_lvl);
		report(session, LOG_DEBUG, DEBUG_PACKET_FLAG, "authen_type=%s (%d)", i2s(map_type, author->authen_type, NULL), author->authen_type);
		report(session, LOG_DEBUG, DEBUG_PACKET_FLAG, "authen_method=%s (%d)", i2s(map_method, author->authen_method, NULL), author->authen_method);
		report(session, LOG_DEBUG, DEBUG_PACKET_FLAG, "service=%s (%d)", i2s(map_service, author->service, NULL), author->service);
		report(session, LOG_DEBUG, DEBUG_PACKET_FLAG,
		       "user_len=%d port_len=%d rem_addr_len=%d arg_cnt=%d", author->user_len, author->port_len, author->rem_addr_len, author->arg_cnt);

		p = (char *) author + TAC_AUTHOR_REQ_FIXED_FIELDS_SIZE;
		argsizep = (unsigned char *) p;
		p += author->arg_cnt;
		report_string(session, LOG_DEBUG, DEBUG_PACKET_FLAG, "user", p, author->user_len);
		p += author->user_len;
		report_string(session, LOG_DEBUG, DEBUG_PACKET_FLAG, "port", p, author->port_len);
		p += author->port_len;
		report_string(session, LOG_DEBUG, DEBUG_PACKET_FLAG, "rem_addr", p, author->rem_addr_len);
		p += author->rem_addr_len;
		dump_args(session, author->arg_cnt, p, argsizep);
	    }
	    break;
	case TAC_PLUS_ACCT:
	    {
		struct acct *acct = tac_payload(hdr, struct acct *);

		report(session, LOG_DEBUG, DEBUG_PACKET_FLAG, "ACCT, priv_lvl=%d flags=0x%x", acct->priv_lvl, acct->flags);
		report(session, LOG_DEBUG, DEBUG_PACKET_FLAG, "authen_type=%s (%d)", i2s(map_type, acct->authen_type, NULL), acct->authen_type);
		report(session, LOG_DEBUG, DEBUG_PACKET_FLAG, "authen_method=%s (%d)", i2s(map_method, acct->authen_method, NULL), acct->authen_method);
		report(session, LOG_DEBUG, DEBUG_PACKET_FLAG, "service=%s (%d)", i2s(map_service, acct->authen_service, NULL), acct->authen_service);
		report(session, LOG_DEBUG, DEBUG_PACKET_FLAG,
		       "user_len=%d port_len=%d rem_addr_len=%d arg_cnt=%d", acct->user_len, acct->port_len, acct->rem_addr_len, acct->arg_cnt);

		p = (char *) acct + TAC_ACCT_REQ_FIXED_FIELDS_SIZE;
		argsizep = (unsigned char *) p;
		p += acct->arg_cnt;
		report_string(session, LOG_DEBUG, DEBUG_PACKET_FLAG, "user", p, acct->user_len);
		p += acct->user_len;
		report_string(session, LOG_DEBUG, DEBUG_PACKET_FLAG, "port", p, acct->port_len);
		p += acct->port_len;
		report_string(session, LOG_DEBUG, DEBUG_PACKET_FLAG, "rem_addr", p, acct->rem_addr_len);
		p += acct->rem_addr_len;
		dump_args(session, acct->arg_cnt, p, argsizep);
	    }
	    break;
	default:
	    report(session, LOG_DEBUG, DEBUG_PACKET_FLAG, "%s: unrecognized header type %d", __func__, hdr->type);
	}
    }
    report(session, LOG_DEBUG, DEBUG_PACKET_FLAG, "%s---<end packet>---%s", common_data.font_green, common_data.font_plain);
}

/* Dump packets originated by tac_plus */
void dump_tacacs_pak(tac_session * session, tac_pak_hdr * hdr)
{
    char *p;

    report(session, LOG_DEBUG, DEBUG_PACKET_FLAG, "%s---<start packet>---%s", common_data.font_green, common_data.font_plain);
    dump_header(session, hdr, 0);

    switch (hdr->type) {
    case TAC_PLUS_AUTHEN:
	{
	    struct authen_reply *authen = tac_payload(hdr, struct authen_reply *);

	    report(session, LOG_DEBUG, DEBUG_PACKET_FLAG,
		   "AUTHEN, status=%d (%s) flags=0x%x", authen->status, summarise_outgoing_packet_type(hdr), authen->flags);
	    report(session, LOG_DEBUG, DEBUG_PACKET_FLAG, "msg_len=%d, data_len=%d", ntohs(authen->msg_len), ntohs(authen->data_len));
	    /* start of variable length data is here */
	    p = (char *) authen + TAC_AUTHEN_REPLY_FIXED_FIELDS_SIZE;
	    report_string(session, LOG_DEBUG, DEBUG_PACKET_FLAG, "msg", p, ntohs(authen->msg_len));
	    p += ntohs(authen->msg_len);
	    report_string(session, LOG_DEBUG, DEBUG_PACKET_FLAG, "data", p, ntohs(authen->data_len));
	}
	break;
    case TAC_PLUS_AUTHOR:
	{
	    struct author_reply *author = tac_payload(hdr, struct author_reply *);
	    unsigned char *argsizep;

	    report(session, LOG_DEBUG, DEBUG_PACKET_FLAG, "AUTHOR/REPLY, status=%d (%s) ", author->status, summarise_outgoing_packet_type(hdr));
	    report(session, LOG_DEBUG, DEBUG_PACKET_FLAG,
		   "msg_len=%d, data_len=%d, arg_cnt=%d", ntohs(author->msg_len), ntohs(author->data_len), author->arg_cnt);
	    p = (char *) author + TAC_AUTHOR_REPLY_FIXED_FIELDS_SIZE;
	    argsizep = (unsigned char *) p;
	    p += author->arg_cnt;
	    report_string(session, LOG_DEBUG, DEBUG_PACKET_FLAG, "msg", p, ntohs(author->msg_len));
	    p += ntohs(author->msg_len);
	    report_string(session, LOG_DEBUG, DEBUG_PACKET_FLAG, "data", p, ntohs(author->data_len));
	    p += ntohs(author->data_len);
	    dump_args(session, author->arg_cnt, p, argsizep);
	}
	break;
    case TAC_PLUS_ACCT:
	{
	    struct acct_reply *acct = tac_payload(hdr, struct acct_reply *);

	    report(session, LOG_DEBUG, DEBUG_PACKET_FLAG,
		   "ACCT/REPLY, status=%d, msg_len=%d, data_len=%d", acct->status, ntohs(acct->msg_len), ntohs(acct->data_len));
	    p = (char *) acct + TAC_ACCT_REPLY_FIXED_FIELDS_SIZE;
	    report_string(session, LOG_DEBUG, DEBUG_PACKET_FLAG, "msg", p, ntohs(acct->msg_len));
	    p += ntohs(acct->msg_len);
	    report_string(session, LOG_DEBUG, DEBUG_PACKET_FLAG, "data", p, ntohs(acct->data_len));
	}
	break;
    default:
	report(session, LOG_DEBUG, DEBUG_PACKET_FLAG, "%s: unrecognized header type %d", __func__, hdr->type);
    }
    report(session, LOG_DEBUG, DEBUG_PACKET_FLAG, "%s---<end packet>---%s", common_data.font_green, common_data.font_plain);
}

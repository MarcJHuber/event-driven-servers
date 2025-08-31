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

/* $Id: headers.h,v 1.427 2021/09/26 06:48:53 marc Exp marc $ */

#ifndef __PROTOCOL_TACACS_H_
#define __PROTOCOL_TACACS_H_

typedef struct {
    u_char version;
#define TAC_PLUS_MAJOR_VER_MASK 0xf0
#define TAC_PLUS_MAJOR_VER      0xc0
#define TAC_PLUS_MINOR_VER_DEFAULT    0x0
#define TAC_PLUS_VER_DEFAULT  (TAC_PLUS_MAJOR_VER | TAC_PLUS_MINOR_VER_DEFAULT)
#define TAC_PLUS_MINOR_VER_ONE    0x01
#define TAC_PLUS_VER_ONE  (TAC_PLUS_MAJOR_VER | TAC_PLUS_MINOR_VER_ONE)

    u_char type;
#define TAC_PLUS_AUTHEN			0x01
#define TAC_PLUS_AUTHOR			0x02
#define TAC_PLUS_ACCT			0x03

    u_char seq_no;		/* packet sequence number */

    u_char flags;		/* packet flags */
#define TAC_PLUS_UNENCRYPTED_FLAG	0x01
#define TAC_PLUS_SINGLE_CONNECT_FLAG	0x04

    int session_id;		/* random, but constant during session */
    int datalength;		/* length of encrypted data following */

    /* datalength bytes of encrypted data */
} __attribute__((__packed__)) tac_pak_hdr;

/* Authentication packet NAS sends to us */

struct authen_start {
    u_char action;
#define TAC_PLUS_AUTHEN_LOGIN    0x01
#define TAC_PLUS_AUTHEN_CHPASS   0x02
#define TAC_PLUS_AUTHEN_SENDPASS 0x03	/* deprecated */
#define TAC_PLUS_AUTHEN_SENDAUTH 0x04

    u_char priv_lvl;
#define TAC_PLUS_PRIV_LVL_MIN 0x0
#define TAC_PLUS_PRIV_LVL_MAX 0xf

    u_char type;
#define TAC_PLUS_AUTHEN_TYPE_ASCII  1
#define TAC_PLUS_AUTHEN_TYPE_PAP    2
#define TAC_PLUS_AUTHEN_TYPE_CHAP   3
#define TAC_PLUS_AUTHEN_TYPE_ARAP   4
#define TAC_PLUS_AUTHEN_TYPE_MSCHAP 5
#define TAC_PLUS_AUTHEN_TYPE_MSCHAPV2 6
#define TAC_PLUS_AUTHEN_TYPE_SSHKEY 240
#define TAC_PLUS_AUTHEN_TYPE_SSHCERT 241
#define TAC_PLUS_AUTHEN_TYPE_EAP 242

    u_char service;
#define TAC_PLUS_AUTHEN_SVC_LOGIN  1
#define TAC_PLUS_AUTHEN_SVC_ENABLE 2
#define TAC_PLUS_AUTHEN_SVC_PPP    3
#define TAC_PLUS_AUTHEN_SVC_ARAP   4
#define TAC_PLUS_AUTHEN_SVC_PT     5
#define TAC_PLUS_AUTHEN_SVC_RCMD   6
#define TAC_PLUS_AUTHEN_SVC_X25    7
#define TAC_PLUS_AUTHEN_SVC_NASI   8
#define TAC_PLUS_AUTHEN_SVC_FWPROXY 9

    u_char user_len;
    u_char port_len;
    u_char rem_addr_len;
    u_char data_len;
    /* <user_len bytes of char data> */
    /* <port_len bytes of char data> */
    /* <rem_addr_len bytes of u_char data> */
    /* <data_len bytes of u_char data> */
} __attribute__((__packed__));

#define TAC_AUTHEN_START_FIXED_FIELDS_SIZE 8

/* Authentication continue packet NAS sends to us */
struct authen_cont {
    u_short user_msg_len;
    u_short user_data_len;
    u_char flags;

#define TAC_PLUS_CONTINUE_FLAG_ABORT 0x01

    /* <user_msg_len bytes of u_char data> */
    /* <user_data_len bytes of u_char data> */
} __attribute__((__packed__));

#define TAC_AUTHEN_CONT_FIXED_FIELDS_SIZE 5

/* Authentication reply packet we send to NAS */
struct authen_reply {
    u_char status;
#define TAC_PLUS_AUTHEN_STATUS_PASS     0x01
#define TAC_PLUS_AUTHEN_STATUS_FAIL     0x02
#define TAC_PLUS_AUTHEN_STATUS_GETDATA  0x03
#define TAC_PLUS_AUTHEN_STATUS_GETUSER  0x04
#define TAC_PLUS_AUTHEN_STATUS_GETPASS  0x05
#define TAC_PLUS_AUTHEN_STATUS_RESTART  0x06
#define TAC_PLUS_AUTHEN_STATUS_ERROR    0x07
#define TAC_PLUS_AUTHEN_STATUS_FOLLOW   0x21

    u_char flags;
#define	TAC_PLUS_REPLY_FLAG_NOECHO		0x01

    u_short msg_len;
    u_short data_len;
    /* <msg_len bytes of char data> */
    /* <data_len bytes of u_char data> */
} __attribute__((__packed__));

#define TAC_AUTHEN_REPLY_FIXED_FIELDS_SIZE 6

/* An authorization request packet */
struct author {
    u_char authen_method;
#define TAC_PLUS_AUTHEN_METH_NOT_SET			0x00
#define TAC_PLUS_AUTHEN_METH_NONE			0x01
#define TAC_PLUS_AUTHEN_METH_KRB5			0x02
#define TAC_PLUS_AUTHEN_METH_LINE			0x03
#define TAC_PLUS_AUTHEN_METH_ENABLE			0x04
#define TAC_PLUS_AUTHEN_METH_LOCAL			0x05
#define TAC_PLUS_AUTHEN_METH_TACACSPLUS			0x06
#define TAC_PLUS_AUTHEN_METH_GUEST			0x08
#define TAC_PLUS_AUTHEN_METH_RADIUS			0x10
#define TAC_PLUS_AUTHEN_METH_KRB4			0x11
#define TAC_PLUS_AUTHEN_METH_RCMD			0x20

    u_char priv_lvl;
    u_char authen_type;
    u_char service;

    u_char user_len;
    u_char port_len;
    u_char rem_addr_len;
    u_char arg_cnt;		/* the number of args */

    /* <arg_cnt u_chars containing the lengths of args 1 to arg n> */
    /* <user_len bytes of char data> */
    /* <port_len bytes of char data> */
    /* <rem_addr_len bytes of u_char data> */
    /* <char data for each arg> */
} __attribute__((__packed__));

#define TAC_AUTHOR_REQ_FIXED_FIELDS_SIZE	8

/* An authorization reply packet */
struct author_reply {
    u_char status;
#define TAC_PLUS_AUTHOR_STATUS_PASS_ADD     0x01
#define TAC_PLUS_AUTHOR_STATUS_PASS_REPL    0x02
#define TAC_PLUS_AUTHOR_STATUS_FAIL         0x10
#define TAC_PLUS_AUTHOR_STATUS_ERROR        0x11

    u_char arg_cnt;
    u_short msg_len;
    u_short data_len;

    /* <arg_cnt u_chars containing the lengths of arg 1 to arg n> */
    /* <msg_len bytes of char data> */
    /* <data_len bytes of char data> */
    /* <char data for each arg> */
} __attribute__((__packed__));

#define TAC_AUTHOR_REPLY_FIXED_FIELDS_SIZE 6

struct acct {
    u_char flags;
#define TAC_PLUS_ACCT_FLAG_MORE     0x1
#define TAC_PLUS_ACCT_FLAG_START    0x2
#define TAC_PLUS_ACCT_FLAG_STOP     0x4
#define TAC_PLUS_ACCT_FLAG_WATCHDOG 0x8

    u_char authen_method;
    u_char priv_lvl;
    u_char authen_type;
    u_char authen_service;
    u_char user_len;
    u_char port_len;
    u_char rem_addr_len;
    u_char arg_cnt;		/* the number of cmd args */
    /* one u_char containing size for each arg */
    /* <user_len bytes of char data> */
    /* <port_len bytes of char data> */
    /* <rem_addr_len bytes of u_char data> */
    /* char data for args 1 ... n */
} __attribute__((__packed__));

#define TAC_ACCT_REQ_FIXED_FIELDS_SIZE 9

struct acct_reply {
    u_short msg_len;
    u_short data_len;
    u_char status;
#define TAC_PLUS_ACCT_STATUS_SUCCESS 0x1
#define TAC_PLUS_ACCT_STATUS_ERROR   0x2
#define TAC_PLUS_ACCT_STATUS_FOLLOW  0x21
} __attribute__((__packed__));

#define TAC_ACCT_REPLY_FIXED_FIELDS_SIZE 5

#define TAC_PLUS_HDR_SIZE 12
#define tac_payload(A,B) ((B) ((u_char *) A + TAC_PLUS_HDR_SIZE))

#endif				/* __PROCOCOL_TACACS_H_ */
/*
 * vim:ts=4
 */

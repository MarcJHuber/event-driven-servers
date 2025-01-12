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

#ifndef __HEADERS_H_
#define __HEADERS_H_

#include "misc/sysconf.h"

#include <ctype.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <errno.h>
#include <limits.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <sysexits.h>
#include <setjmp.h>

#ifdef WITH_PCRE2
#include <pcre2.h>
#endif

#include "misc/radix.h"
#include "misc/rb.h"
#include "misc/io_sched.h"
#include "misc/sig_segv.h"
#include "misc/setproctitle.h"
#include "misc/memops.h"
#include "mavis/set_proctitle.h"
#include "mavis/mavis.h"
#include "misc/net.h"

#ifdef WITH_DNS
#include "misc/io_dns_revmap.h"
#endif

#define MD5_LEN           16
#define MSCHAP_DIGEST_LEN 49

#if defined(WITH_SSL) && OPENSSL_VERSION_NUMBER < 0x30000000
#undef WITH_SSL
#warning Disabling OpenSSL support. Please upgrade to version 3.0
#endif

struct context;
struct tac_acl;

struct realm;
typedef struct realm tac_realm;

#define TAC_PLUS_PRIV_LVL_MIN 0x0
#define TAC_PLUS_PRIV_LVL_MAX 0xf

struct pwdat {
    enum token type;
    char value[1];
};

#define TRISTATE_DUNNO	0
#define TRISTATE_YES	1
#define TRISTATE_NO	2
#define BISTATE_YES	1
#define BISTATE_NO	0
#define BISTATE(A) u_int A:1
#define TRISTATE(A) u_int A:2

struct tac_key {
    struct tac_key *next;
    int len;
    u_int line;			/* configuration file line number */
    time_t warn;
    char key[1];
};

struct tac_host;
typedef struct tac_host tac_host;

struct log_item {
    enum token token;
    char *text;
    str_t separator;
    struct log_item *next;
};

enum user_message_enum { UM_PASSWORD = 0, UM_RESPONSE, UM_PASSWORD_OLD, UM_PASSWORD_NEW, UM_PASSWORD_ABORT, UM_PASSWORD_AGAIN,
    UM_PASSWORD_NOMATCH, UM_PASSWORD_MINREQ, UM_PERMISSION_DENIED, UM_ENABLE_PASSWORD, UM_PASSWORD_CHANGE_DIALOG, UM_PASSWORD_CHANGED,
    UM_BACKEND_FAILED, UM_CHANGE_PASSWORD, UM_ACCOUNT_EXPIRES, UM_PASSWORD_INCORRECT, UM_RESPONSE_INCORRECT,
    UM_USERNAME, UM_USER_ACCESS_VERIFICATION, UM_DENIED_BY_ACL, UM_PASSWORD_EXPIRED, UM_PASSWORD_EXPIRES, UM_MAVIS_PARSE_ERROR, UM_MAX
};

#define TAC_NAME_ATTRIBUTES str_t name

struct memlist;
typedef struct memlist memlist_t;

struct tac_tags;
struct tac_tag;
typedef struct tac_tags tac_tags;
typedef struct tac_tag tac_tag;
struct mem;
typedef struct mem mem_t;

struct tac_host {
    TAC_NAME_ATTRIBUTES;
    u_int line;			/* configuration file line number */
    struct {
	TRISTATE(anon_enable);	/* permit anonymous enable */
	TRISTATE(lookup_revmap_nac);	/* lookup reverse mapping in DNS */
	TRISTATE(lookup_revmap_nas);	/* lookup reverse mapping in DNS */
	TRISTATE(authfallback);	/* authentication fallback permitted? */
	TRISTATE(single_connection);	/* single-connection permitted? */
	TRISTATE(cleanup_when_idle);	/* cleanup context when idle */
	TRISTATE(augmented_enable);	/* one-step enable for $enab.* user */
	TRISTATE(map_pap_to_login);
	TRISTATE(authz_if_authc);
	TRISTATE(try_mavis);
	BISTATE(complete);
	BISTATE(visited);
	BISTATE(skip_parent_script);
	u_char bug_compatibility;
    } __attribute__((__packed__));
    tac_host *parent;
    tac_realm *target_realm;
    mem_t *mem;
    struct tac_key *key;
    struct tac_key *radius_key;
    struct log_item *motd;
    struct log_item *welcome_banner;	/* prompt */
    struct log_item *welcome_banner_fallback;	/* fallback prompt */
    struct log_item *reject_banner;
    struct log_item *authfail_banner;
    struct pwdat **enable;
    tac_tags *tags;
    int tcp_timeout;		/* tcp connection idle timeout */
    int udp_timeout;		/* udp connection idle timeout */
    int session_timeout;	/* session idle timeout */
    int context_timeout;	/* shell context idle timeout */
    int dns_timeout;
    int authen_max_attempts;	/* maximum number of password retries per session */
    int max_rounds;		/* maximum number of packet exchanges */
    tac_realm *realm;
    struct mavis_action *action;
    char **user_messages;
    time_t password_expiry_warning;
    u_int debug;
#ifdef WITH_SSL
    char *tls_psk_id;
    u_char *tls_psk_key;
    size_t tls_psk_key_len;
#endif
};

struct tac_net;
typedef struct tac_net tac_net;

struct tac_net {
    TAC_NAME_ATTRIBUTES;
    u_int line;			/* configuration file line number */
    enum token res;		/* permit or deny */
    tac_net *parent;
    radixtree_t *nettree;
     BISTATE(visited);
};

enum pw_ix { PW_LOGIN = 0, PW_PAP, PW_CHAP, PW_MSCHAP, PW_LOGIN_FALLBACK, PW_PAP_FALLBACK, PW_MAVIS };

enum hint_enum { hint_failed = 0, hint_denied, hint_nopass, hint_expired, hint_nosuchuser, hint_succeeded, hint_permitted, hint_no_cleartext,
    hint_backend_error, hint_denied_profile, hint_failed_password_retry, hint_bug, hint_abort, hint_denied_by_acl,
    hint_invalid_challenge_length, hint_weak_password, hint_badsecret, hint_max
};

struct tac_groups;
struct tac_group;
typedef struct tac_groups tac_groups;
typedef struct tac_group tac_group;

struct tac_profile {
    TAC_NAME_ATTRIBUTES;
    mem_t *mem;
    struct tac_profile *parent;
    struct pwdat **enable;
    struct mavis_action *action;
    tac_realm *realm;
    struct {
	TRISTATE(hushlogin);
	BISTATE(complete);
	BISTATE(visited);
	BISTATE(skip_parent_script);
	BISTATE(dynamie);
    } __attribute__((__packed__));
    u_int line;			/* configuration file line number */
    u_int debug;		/* debug flags */
};

struct ssh_key;
struct ssh_key_id;
struct tac_alias;
typedef struct tac_alias tac_alias;

/* A user definition. */
typedef struct {
    TAC_NAME_ATTRIBUTES;
    char *msg;			/* message for this user */
    u_int line;			/* line number defined on */
    time_t valid_from;		/* validity period start */
    time_t valid_until;		/* validity period end */
    time_t dynamic;		/* caching timeout. Always 0 for static users */
    struct pwdat **enable;
    struct pwdat *passwd[PW_MAVIS + 1];
    struct ssh_key *ssh_key;
    struct ssh_key_id *ssh_key_id;
    tac_groups *groups;
    tac_tags *tags;
    mem_t *mem;
    tac_realm *realm;
    tac_alias *alias;
    u_int debug;		/* debug flags */
    struct {
	TRISTATE(chalresp);
	TRISTATE(hushlogin);
	BISTATE(passwd_oneshot);
	BISTATE(fallback_only);
	BISTATE(rewritten_only);
    } __attribute__((__packed__));
    av_ctx *avc;
    struct tac_profile *profile;
} tac_user;

struct tac_alias {
    TAC_NAME_ATTRIBUTES;
    u_int line;
    tac_user *user;
    tac_alias *next;
};

struct rad_dict;

struct config {
    mode_t mask;		/* file mask */
    str_t hostname;
    int retire;			/* die after <retire> invocations */
    int ctx_lru_threshold;	/* purge lru context if number reached */
    time_t suicide;		/* when to commit suicide */
    tac_realm *default_realm;	/* actually the one called "default" */
    struct rad_dict *rad_dict;
};

struct tac_acl {
    TAC_NAME_ATTRIBUTES;
    struct mavis_action *action;
};

struct tac_rule {
    struct tac_rule *next;
    u_int enabled:1;
    struct tac_acl acl;
};

struct sni_list;

struct realm {
    TAC_NAME_ATTRIBUTES;
    u_int line;			/* configuration file line number */
    rb_tree_t *acctlog;
    rb_tree_t *accesslog;
    rb_tree_t *authorlog;
    rb_tree_t *connlog;
    rb_tree_t *rad_accesslog;
    rb_tree_t *rad_acctlog;
    rb_tree_t *usertable;
    rb_tree_t *aliastable;
    rb_tree_t *profiletable;
    rb_tree_t *acltable;
    rb_tree_t *logdestinations;
    rb_tree_t *rewrite;
    rb_tree_t *groups_by_name;
    rb_tree_t *hosttable;
    rb_tree_t *nettable;
    rb_tree_t *timespectable;
    rb_tree_t *realms;
    rb_tree_t *dns_tree_a;
    radixtree_t *hosttree;
    tac_realm *parent;
    mavis_ctx *mcx;
    struct tac_rule *rules;
    tac_host *default_host;
    struct {
	BISTATE(complete);

	TRISTATE(chalresp);	/* enable challenge-response authentication */
	TRISTATE(chalresp_noecho);	/* enable local echo for response */
	TRISTATE(chpass);	/* enable password change dialogue */
	TRISTATE(mavis_userdb);	/* use MAVIS for user authentication, too */
	TRISTATE(mavis_noauthcache);	/* don't do backend password caching */
	TRISTATE(mavis_pap);
	TRISTATE(mavis_login);
	TRISTATE(mavis_pap_prefetch);
	TRISTATE(mavis_login_prefetch);
	TRISTATE(script_profile_parent_first);
	TRISTATE(script_host_parent_first);
	TRISTATE(script_realm_parent_first);
	TRISTATE(haproxy_autodetect);

	TRISTATE(allowed_protocol_radius_udp);
	TRISTATE(allowed_protocol_radius_tcp);
	TRISTATE(allowed_protocol_radius_tls);
	TRISTATE(allowed_protocol_radius_dtls);
	TRISTATE(allowed_protocol_tacacs_tcp);
	TRISTATE(allowed_protocol_tacacs_tls);

	BISTATE(use_tls_psk);
	BISTATE(visited);
	BISTATE(skip_parent_script);
    } __attribute__((__packed__));
    int dns_caching_period;	/* dns caching period */
    time_t dnspurge_last;
    int caching_period;		/* user caching period */
    int warning_period;		/* password expiration warning period */
    int backend_failure_period;
    struct tac_acl *mavis_user_acl;
    struct tac_acl *enable_user_acl;
    struct tac_acl *password_acl;
    time_t last_backend_failure;
#ifdef WITH_PCRE2
    pcre2_code *password_minimum_requirement;
#endif
#ifdef WITH_SSL
    SSL_CTX *tls;
    SSL_CTX *dtls;
    char *tls_cert;
    char *tls_key;
    char *tls_pass;
    char *tls_ciphers;
    char *tls_cafile;
    int tls_verify_depth;
     TRISTATE(tls_accept_expired);
     TRISTATE(tls_autodetect);
     TRISTATE(tls_sni_required);
    struct sni_list *sni_list;
    u_char *alpn_vec;
    size_t alpn_vec_len;
#endif
    u_int debug;
    int rulecount;
    struct io_dns_ctx *idc;
    radixtree_t *dns_tree_ptr[3];	// 0: static, 1-2: dynamic
};

struct tac_session;
typedef struct tac_session tac_session;

///// TACACS+ header format

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

///// RADIUS header format

typedef struct {
    uint8_t code;
    uint8_t identifier;
    uint16_t length;
    union {
	    u_char authenticator[16];
	    uint32_t token;
    };
} __attribute__((__packed__)) rad_pak_hdr;
#define RADIUS_HDR_SIZE sizeof(rad_pak_hdr)

// various #defines, mostly derived from RFC2856/RFC2866. 

#define RADIUS_CODE_ACCESS_REQUEST		1
#define RADIUS_CODE_ACCESS_ACCEPT		2
#define RADIUS_CODE_ACCESS_REJECT		3
#define RADIUS_CODE_ACCOUNTING_REQUEST		4
#define RADIUS_CODE_ACCOUNTING_RESPONSE		5
#define RADIUS_CODE_STATUS_SERVER		12
#define RADIUS_CODE_STATUS_CLIENT		13
#define RADIUS_CODE_PROTOCOL_ERROR		52

#define RADIUS_A_USER_NAME			1
#define RADIUS_A_USER_PASSWORD			2
#define RADIUS_A_CHAP_PASSWORD			3
#define RADIUS_A_NAS_IP_ADDRESS			4
#define RADIUS_A_NAS_PORT			5
#define RADIUS_A_SERVICE_TYPE			6
#define RADIUS_A_LOGIN_IP_HOST			14
#define RADIUS_A_LOGIN_SERVICE			15
#define RADIUS_A_LOGIN_TCP_PORT			16
#define RADIUS_A_REPLY_MESSAGE			18
#define RADIUS_A_STATE				24
#define RADIUS_A_CLASS				25
#define RADIUS_A_VENDOR_SPECIFIC		26
#define RADIUS_A_TERMINATION_ACTION		29
#define RADIUS_A_CALLED_STATION_ID		30
#define RADIUS_A_CALLING_STATION_ID		31
#define RADIUS_A_NAS_IDENTIFIER			32
#define RADIUS_A_NAS_PORT_TYPE			61
#define RADIUS_A_MESSAGE_AUTHENTICATOR		80
#define RADIUS_A_NAS_PORT_ID			87

#define RADIUS_A_ERROR_CAUSE					101
#define RADIUS_V_ERROR_CAUSE_UNSUPPORTED_ATTRIBUTE		401
#define RADIUS_V_ERROR_CAUSE_MISSING_ATTRIBUTE			402
#define RADIUS_V_ERROR_CAUSE_NAS_IDENTIFICATION_MISMATCH	403
#define RADIUS_V_ERROR_CAUSE_INVALID_REQUEST			404
#define RADIUS_V_ERROR_CAUSE_UNSUPPORTED_SERVICE		405
#define RADIUS_V_ERROR_CAUSE_UNSUPPORTED_EXTENSIION		406
#define RADIUS_V_ERROR_CAUSE_INVALID_ATTRIBUTE_NAME		407
#define RADIUS_V_ERROR_CAUSE_ADMINISTRATIVELY_RROHIBITED	501
#define RADIUS_V_ERROR_CAUSE_SESSION_CONTEXT_NOT_FOUNF		503
#define RADIUS_V_ERROR_CAUSE_RESOURCES_UNAVAILABLE		506
#define RADIUS_V_ERROR_CAUSE_REQUEST_INITITED			507
#define RADIUS_V_ERROR_CAUSE_RESPONSE_TOO_BIG			601

#define RADIUS_A_ACCT_STATUS_TYPE			40
#define RADIUS_V_ACCT_STATUS_TYPE_START			1
#define RADIUS_V_ACCT_STATUS_TYPE_STOP			2
#define RADIUS_V_ACCT_STATUS_TYPE_INTERIM_UPDATE	3
#define RADIUS_V_ACCT_STATUS_TYPE_ACCOUNTING_ON		7
#define RADIUS_V_ACCT_STATUS_TYPE_ACCOUNTING_OFF	8

#define RADIUS_A_ACCT_DELAY_TIME	41
#define RADIUS_A_ACCT_INPUT_OCTETS	42
#define RADIUS_A_ACCT_OUTPUT_OCTETS	43
#define RADIUS_A_ACCT_SESSION_ID	44

#define RADIUS_A_ACCT_AUTHENTIC		45
#define RADIUS_V_ACCT_AUTHENTIC_RADIUS	1
#define RADIUS_V_ACCT_AUTHENTIC_LOCAL	2
#define RADIUS_V_ACCT_AUTHENTIC_REMOTE	3

#define RADIUS_A_ACCT_SESSION_TIME	46
#define RADIUS_A_ACCT_INPUT_PACKETS	47
#define RADIUS_A_ACCT_OUTPUT_PACKETS	48
#define RADIUS_A_ACCT_TERMINATE_CAUSE	49
#define RADIUS_A_ACCT_MULTI_SESSION_ID	50
#define RADIUS_A_ACCT_LINK_COUNT	51
#define RADIUS_A_ACCT_INTERIM_INTERVAL	85

struct radius_data {
    rad_pak_hdr *pak_in;
    size_t pak_in_len;
    u_char protocol;		// AF_INET, AF_INET6
    short src_port;		// host byte order
    short dst_port;		// host byte order
    u_char src[16];
    u_char dst[16];
    size_t data_len;
    union {
	rad_pak_hdr pak;
	u_char data[4096];
    };
};

#define RADIUS_DATA(A) (((u_char *)(A)) + RADIUS_HDR_SIZE)
#define RADIUS_DATA_LEN(A) (ntohs(((rad_pak_hdr *)A)->length) - RADIUS_HDR_SIZE)

/* Authentication packet NAS sends to us */

struct authen_start {
    u_char action;
#define TAC_PLUS_AUTHEN_LOGIN    0x01
#define TAC_PLUS_AUTHEN_CHPASS   0x02
#define TAC_PLUS_AUTHEN_SENDPASS 0x03	/* deprecated */
#define TAC_PLUS_AUTHEN_SENDAUTH 0x04

    u_char priv_lvl;

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

union pak_hdr {
    tac_pak_hdr tac;
    rad_pak_hdr rad;
    u_char uchar[1];
};

struct tac_pak {
    struct tac_pak *next;
    ssize_t offset;
    ssize_t length;
    time_t delay_until;
    union pak_hdr pak;
};

typedef struct tac_pak tac_pak;
typedef struct rad_pak rad_pak;

struct author_data {
    char *admin_msg;		/* admin message (optional) */
    int status;			/* return status */
    int in_cnt;			/* input arg count */
    char **in_args;		/* input arguments */
    int out_cnt;		/* output arg cnt */
    char **out_args;		/* output arguments */
    int is_shell;
    int is_cmd;
};

struct authen_data {
    u_char *data;
    size_t data_len;
    char *msg;
    size_t msg_len;
    int iterations;
    void (*authfn)(tac_session *);
};

struct mavis_data;
struct mavis_ctx_data;

typedef struct tac_profile tac_profile;

struct tac_session {
    struct context *ctx;
    mem_t *mem;
    tac_user *user;
    struct in6_addr nac_address;	/* host byte order */
    str_t username;
    str_t username_orig;
    str_t msg;
    str_t user_msg;
    str_t port;
    str_t nac_addr_ascii;
    str_t nac_dns_name;		/* DNS reverse mapping for NAC */
    str_t action;
    str_t service;
    str_t protocol;
    str_t hint;
    str_t cmdline;
    str_t message;		// to the user
    str_t label;
    str_t *rulename;
    str_t *type;
    str_t *authen_action;
    str_t *authen_type;
    str_t *authen_service;
    str_t *authen_method;
    str_t *msgid;
    str_t *result;
    str_t *acct_type;
    u_char arg_cnt;
    u_char *arg_len;
    u_char *argp;
    u_char arg_out_cnt;
    u_char *arg_out_len;
    u_char *argp_out;
    u_int priv_lvl;		/* requested privilege level */
    char *password;
    char *password_new;
    char *password_bad;
    char *challenge;
    char *motd;
    char *welcome_banner;
    char *ssh_key_hash;
    char *ssh_key_id;
    int session_id;
    time_t session_timeout;
    struct author_data *author_data;
    struct authen_data *authen_data;
    struct mavis_data *mavis_data;
    struct radius_data *radius_data;
    struct pwdat *enable;
    tac_profile *profile;
    struct {
	BISTATE(nac_addr_valid);
	BISTATE(flag_mavis_info);
	BISTATE(flag_mavis_auth);
	BISTATE(flag_chalresp);
	BISTATE(mavis_pending);
	BISTATE(revmap_pending);
	BISTATE(revmap_timedout);
	BISTATE(enable_getuser);
	BISTATE(password_bad_again);
	BISTATE(passwd_mustchange);
	BISTATE(passwd_changeable);
	BISTATE(user_is_session_specific);
	BISTATE(username_rewritten);
	BISTATE(chpass);
	BISTATE(authorized);
	BISTATE(eval_log_raw);
    } __attribute__((__packed__));
    enum token mavisauth_res;
    u_int authfail_delay;
    u_int debug;
    u_char seq_no;		/* seq. no. of last packet exchanged */
    u_char version;
    u_char pak_authen_type;
    u_char pak_authen_method;
    void (*resumefn)(tac_session *);
    char **attrs_m;		/* mandatory */
    char **attrs_o;		/* optional (from NAS) */
    char **attrs_a;		/* add optional (to NAS) */
    int cnt_m;
    int cnt_o;
    int cnt_a;
    enum token attr_dflt;
    time_t password_expiry;
    u_long mavis_latency;
};

struct user_profile_cache {
    tac_user *user;
    tac_profile *profile;
    time_t valid_until;
    enum token res;
    uint32_t crc32;
};

struct context {
    int sock;			/* socket for this connection */
    io_context_t *io;
    tac_host *host;
    tac_pak *in;
    tac_pak *out;
    tac_pak *delayed;
    mem_t *mem;			/* memory pool */
    rb_tree_t *sessions;
    rb_tree_t *shellctxcache;
    tac_realm *realm;
    struct mavis_ctx_data *mavis_data;

    str_t device_dns_name;	// device
    str_t device_addr_ascii;
    str_t device_port_ascii;
    struct in6_addr device_addr;	// for binary comparisions, in host byte order

    str_t server_addr_ascii;
    str_t server_port_ascii;

    str_t proxy_addr_ascii;	// .txt == NULL if not proxied

    str_t peer_addr_ascii;	// TCP/UDP peer
    str_t peer_port_ascii;

    u_char flags;
    union pak_hdr hdr;
    ssize_t hdroff;
    struct tac_key *key;
    time_t last_io;
    struct radius_data *radius_data;
#ifdef WITH_SSL
    SSL *tls;
    struct {
	TRISTATE(alpn_passed);
	BISTATE(sni_passed);
    } __attribute__((__packed__));
    str_t tls_conn_version;
    str_t tls_conn_cipher;
    str_t tls_peer_cert_issuer;
    str_t tls_peer_cert_subject;
    str_t tls_conn_cipher_strength;
    str_t tls_peer_cn;
    str_t tls_psk_identity;
    str_t tls_sni;
    char **tls_peer_cert_san;
    size_t tls_peer_cert_san_count;
    BIO *rbio;
#endif
    u_int tls_versions;

    str_t *msgid;
    str_t *acct_type;
    str_t vrf;
#define USER_PROFILE_CACHE_SIZE 8
    char *hint;
    struct user_profile_cache user_profile_cache[USER_PROFILE_CACHE_SIZE];
    struct {
	TRISTATE(cleanup_when_idle);	/* cleanup context when idle */
	BISTATE(unencrypted_flag);	/* not MD5 encrypted? */
	BISTATE(single_connection_flag);	/* single-connection enabled? */
	BISTATE(single_connection_test);	/* single-connection capable, but not telling? */
	BISTATE(single_connection_did_warn);
	BISTATE(dying);
	BISTATE(key_fixed);
	BISTATE(revmap_pending);
	BISTATE(revmap_timedout);
	BISTATE(use_tls);
	BISTATE(use_dtls);
	BISTATE(mavis_pending);
	BISTATE(mavis_tried);
	BISTATE(rad_acct);
	BISTATE(reset_tcp);
	BISTATE(udp);
	BISTATE(radius_1_1);
    } __attribute__((__packed__));
    enum token mavis_result;
    enum token aaa_protocol;
    u_int id;
    u_int bug_compatibility;
    u_int debug;
    u_long mavis_latency;
    u_char *inject_buf;
    size_t inject_len;
    size_t inject_off;
    struct context *lru_prev;
    struct context *lru_next;
};

struct logfile;

struct context_logfile {
    int fd;
    io_context_t *io;
    struct buffer *buf;
    pid_t pid;
    int dying;
    struct logfile *lf;
    char path[1];		/* current log file name */
};

void cleanup(struct context *, int);

/* acct.c */
void accounting(tac_session *, tac_pak_hdr *);
void rad_acct(tac_session *);

/* report.c */
void report_string(tac_session *, int, int, char *, char *, int);
void report_hex(tac_session *, int, int, u_char *, int);
void report(tac_session *, int, int, char *, ...)
    __attribute__((format(printf, 4, 5)));

/* packet.c */
void send_authen_reply(tac_session *, int, char *, int, u_char *, int, u_char);
void send_authen_error(tac_session *, char *, ...) __attribute__((format(printf, 2, 3)));
void send_acct_reply(tac_session *, u_char, char *, char *);
void send_author_reply(tac_session *, u_char, char *, char *, int, char **);
void rad_send_authen_reply(tac_session *, u_char, char *);
void rad_send_acct_reply(tac_session * session);
void rad_send_error(tac_session * session, uint32_t cause);

int tac_exit(int) __attribute__((noreturn));

void log_exec(tac_session *, struct context *, enum token, time_t);
void log_add(struct sym *, rb_tree_t **, char *, tac_realm *);
int logs_flushed(tac_realm *);

/* dump.c */
char *summarise_outgoing_packet_type(tac_pak_hdr *);
void dump_nas_pak(tac_session *, int);
void dump_tacacs_pak(tac_session *, tac_pak_hdr *);
void dump_rad_pak(tac_session *, rad_pak_hdr *);

/* authen.c */
void authen(tac_session *, tac_pak_hdr *);
void rad_authen(tac_session *);
void rad_set_fields(tac_session * session);
void authen_init(void);

/* author.c */
void author(tac_session *, tac_pak_hdr *);
enum token author_eval_host(tac_session * session, tac_host * h, int parent_first);
enum token author_eval_profile(tac_session * session, tac_profile * p, int parent_first);


/* config.c */
int cfg_get_enable(tac_session *, struct pwdat **);

void parse_decls(struct sym *);
void parse_user_final(tac_user *);
int parse_user_profile_fmt(struct sym *, tac_user *, char *, ...);
int parse_host_profile(struct sym *, tac_realm *, tac_host *);

void parse_log(struct sym *, tac_realm *);
char *eval_log_format(tac_session *, struct context *, struct logfile *, struct log_item *, time_t, size_t *);
str_t *eval_log_format_privlvl(tac_session *, struct context *, struct logfile *);
struct log_item *parse_log_format_inline(char *, char *, int);

tac_user *new_user(char *, enum token, tac_realm *);
int compare_name(const void *, const void *);
void free_user(tac_user *);
void cfg_init(void);
enum token tac_keycode(char *);
enum token eval_ruleset(tac_session *, tac_realm *);

static __inline__ int minimum(int a, int b)
{
    return (a < b) ? a : b;
}

void tac_read(struct context *, int);
void tac_write(struct context *, int);
void rad_read(struct context *, int);
int rad_get(tac_session * session, int vendorid, int id, enum token, void *, size_t *);
int rad_get_password(tac_session * session, char **val, size_t *val_len);
void rad_attr_val_dump(mem_t * mem, u_char * data, size_t data_len, char **buf, size_t *buf_len, struct rad_dict *dict, char *separator,
		       size_t separator_len);

void rad_dict_get_val(int dict_id, int attr_id, int val_id, char **s, size_t *s_len);

struct rad_dict *rad_dict_lookup_by_id(int vendorid);
struct rad_dict_attr *rad_dict_attr_lookup_by_id(struct rad_dict *dict, int id);
struct rad_dict_val *rad_dict_val_lookup_by_id(struct rad_dict_attr *attr, int id);

void rad_udp_inject(struct context *);
ssize_t recv_inject(struct context *ctx, void *buf, size_t len, int flags);

void cleanup_session(tac_session *);
struct log_item *parse_log_format(struct sym *, mem_t *);

void mavis_lookup(tac_session *, void (*)(tac_session *), const char *const, enum pw_ix);
void mavis_ctx_lookup(struct context *, void (*)(struct context *), const char *const);
tac_user *lookup_user(tac_session *);
mavis_ctx *lookup_mcx(tac_realm *);
tac_realm *lookup_realm(char *, tac_realm *);
radixtree_t *lookup_hosttree(tac_realm *);

#define LOG_ACCESS 0x80000000

struct revmap {
    time_t ttl;
    char *name;
};

void get_revmap_nac(tac_session *);
void get_revmap_nas(tac_session *);
void add_revmap(tac_realm *, struct in6_addr *, char *, int, int);
void free_reverse(void *, void *);
void resume_session(tac_session *, int);
void get_pkt_data(tac_session *, struct authen_start *, struct author *);

enum token tac_script_eval_r(tac_session *, struct mavis_action *);
void tac_script_expire_exec_context(struct context *);
void tac_script_set_exec_context(tac_session *, char *);
char *tac_script_get_exec_context(tac_session *);
enum token eval_tac_acl(tac_session *, struct tac_acl *);
tac_host *lookup_host(char *, tac_realm *);

int query_mavis_info(tac_session *, void (*)(tac_session *), enum pw_ix);
void expire_dynamic_users(tac_realm *);
void drop_mcx(tac_realm *);
void init_mcx(tac_realm *);
void complete_host(tac_host *);
void complete_realm(tac_realm *);

void attr_add(tac_session *, char ***, int *, char *, size_t);

enum token validate_ssh_hash(tac_session *, char *, char **);
enum token validate_ssh_key_id(tac_session *);

tac_realm *lookup_sni(const char *, size_t, tac_realm *, char **, size_t *);

void eval_args(tac_session *, u_char *, u_char *, size_t);

void init_host(tac_host *, tac_host *, tac_realm *, int);

void context_lru_append(struct context *);

void users_dec(void);

void update_bio(struct context *);

ssize_t sendto_spoof(sockaddr_union * from_addr, sockaddr_union * dest_addr, void *buf, size_t len);

extern struct config config;
extern int die_when_idle;

#define CLIENT_BUG_INVALID_START_DATA	0x01
#define CLIENT_BUG_BAD_VERSION		0x02
#define CLIENT_BUG_TLS_OBFUSCATED	0x04
#define CLIENT_BUG_HEADER_LENGTH	0x08

#endif				/* __HEADERS_H_ */
/*
 * vim:ts=4
 */

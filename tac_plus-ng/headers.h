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
#include "mavis/set_proctitle.h"
#include "mavis/mavis.h"
#include "misc/net.h"

#ifdef WITH_DNS
#include "misc/io_dns_revmap.h"
#endif

#define MD5_LEN           16
#define MSCHAP_DIGEST_LEN 49

#if OPENSSL_VERSION_NUMBER < 0x30000000
# undef WITH_SSL
# warning Disabling OpenSSL support. Please upgrade to version 3.0
#endif

#ifdef WITH_SSL
#undef WITH_TLS
#endif

struct context;
struct tac_acl;
struct tac_acllist;

struct realm;
typedef struct realm tac_realm;
struct rewrite_expr;
typedef struct rewrite_expr tac_rewrite_expr;
struct rewrite;
typedef struct rewrite tac_rewrite;

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
    char *separator;
    size_t separator_len;
    struct log_item *next;
};

enum user_message_enum { UM_PASSWORD = 0, UM_RESPONSE, UM_PASSWORD_OLD, UM_PASSWORD_NEW, UM_PASSWORD_ABORT, UM_PASSWORD_AGAIN,
    UM_PASSWORD_NOMATCH, UM_PASSWORD_MINREQ, UM_PERMISSION_DENIED, UM_ENABLE_PASSWORD, UM_PASSWORD_CHANGE_DIALOG,
    UM_BACKEND_FAILED, UM_CHANGE_PASSWORD, UM_ACCOUNT_EXPIRES, UM_PASSWORD_INCORRECT, UM_RESPONSE_INCORRECT,
    UM_USERNAME, UM_USER_ACCESS_VERIFICATION, UM_DENIED_BY_ACL, UM_MAX
};

struct tac_host {
    u_int line;			/* configuration file line number */
     TRISTATE(anon_enable);	/* permit anonymous enable */
     TRISTATE(lookup_revmap_nac);	/* lookup reverse mapping in DNS */
     TRISTATE(lookup_revmap_nas);	/* lookup reverse mapping in DNS */
     TRISTATE(authfallback);	/* authentication fallback permitted? */
     TRISTATE(single_connection);	/* single-connection permitted? */
     TRISTATE(cleanup_when_idle);	/* cleanup context when idle */
     TRISTATE(augmented_enable);	/* one-step enable for $enab.* user */
     TRISTATE(map_pap_to_login);
     TRISTATE(authz_if_authc);
     BISTATE(complete);
     BISTATE(visited);
    u_int bug_compatibility;
    char *name;			/* host name */
    size_t name_len;
    tac_host *parent;
    struct tac_key *key;
    struct log_item *motd;
    struct log_item *welcome_banner;	/* prompt */
    struct log_item *welcome_banner_fallback;	/* fallback prompt */
    struct log_item *reject_banner;
    struct pwdat **enable;
    int tcp_timeout;		/* tcp connection idle timeout */
    int session_timeout;	/* session idle timeout */
    int context_timeout;	/* shell context idle timeout */
    int dns_timeout;
    int authen_max_attempts;	/* maximum number of password retries per session */
    tac_realm *realm;
    tac_rewrite *rewrite_user;
    struct tac_script_action *action;
    char **user_messages;
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
    u_int line;			/* configuration file line number */
    char *name;			/* host name */
    enum token res;		/* permit or deny */
    tac_net *parent;
    radixtree_t *nettree;
     BISTATE(visited);
};

enum pw_ix { PW_LOGIN = 0, PW_PAP, PW_CHAP, PW_MSCHAP, PW_MAVIS };

enum hint_enum { hint_failed = 0, hint_denied, hint_nopass, hint_expired, hint_nosuchuser, hint_succeeded, hint_permitted, hint_no_cleartext,
    hint_backend_error, hint_denied_profile, hint_failed_password_retry, hint_bug, hint_abort, hint_denied_by_acl,
    hint_invalid_challenge_length, hint_weak_password, hint_max
};

struct tac_groups;
struct tac_group;
typedef struct tac_groups tac_groups;
typedef struct tac_group tac_group;

struct tac_profile {
    char *name;			/* profile name */
    size_t name_len;
    u_int line;			/* line number defined on */
    struct pwdat **enable;
    struct tac_script_action *action;
    tac_realm *realm;
     TRISTATE(hushlogin);
    u_int debug;		/* debug flags */
};

struct memlist;
typedef struct memlist memlist_t;
struct ssh_key;
struct ssh_key_id;

/* A user or group definition. */
typedef struct {
    char *msg;			/* message for this user */
    u_int line;			/* line number defined on */
    time_t valid_from;		/* validity period start */
    time_t valid_until;		/* validity period end */
    time_t dynamic;		/* caching timeout. Always 0 for static users */
    struct pwdat **enable;
    struct tac_acllist *passwd_acllist;
    struct ssh_key *ssh_key;
    struct ssh_key_id *ssh_key_id;
    tac_groups *groups;
    memlist_t *memlist;
    tac_realm *realm;
    u_int debug;		/* debug flags */
     TRISTATE(chalresp);
     TRISTATE(hushlogin);
     BISTATE(passwd_oneshot);
     BISTATE(fallback_only);
    av_ctx *avc;
    char *name;			/* username */
    size_t name_len;
} tac_user;

struct config {
    mode_t mask;		/* file mask */
    char *hostname;
    size_t hostname_len;
    int retire;			/* die after <retire> invocations */
    time_t suicide;		/* when to commit suicide */
    tac_realm *default_realm;	/* actually the one called "default" */
};

struct rewrite_expr {
    char *name;
#ifdef WITH_PCRE2
    pcre2_code *code;
    PCRE2_SPTR replacement;
#endif
    struct rewrite_expr *next;
};

struct rewrite {
    char *name;
    tac_rewrite_expr *expr;
};

struct tac_acl {
    struct tac_script_action *action;
    char *name;
    size_t name_len;
};

struct tac_rule {
    struct tac_rule *next;
    u_int enabled:1;
    struct tac_acl acl;
};

struct realm {
    u_int line;			/* configuration file line number */
    char *name;
    size_t name_len;
    rb_tree_t *acctlog;
    rb_tree_t *accesslog;
    rb_tree_t *authorlog;
    rb_tree_t *connlog;
    rb_tree_t *usertable;
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

     BISTATE(complete);

     TRISTATE(chalresp);	/* enable challenge-response authentication */
     TRISTATE(chalresp_noecho);	/* enable local echo for response */
     TRISTATE(chpass);		/* enable password change dialogue */
     TRISTATE(mavis_userdb);	/* use MAVIS for user authentication, too */
     TRISTATE(mavis_noauthcache);	/* don't do backend password caching */
     TRISTATE(mavis_pap);
     TRISTATE(mavis_login);
     TRISTATE(mavis_pap_prefetch);
     TRISTATE(mavis_login_prefetch);
     BISTATE(use_tls_psk);
     BISTATE(visited);
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
#ifdef WITH_TLS
    struct tls *tls;
    struct tls_config *tls_cfg;
#endif
#ifdef WITH_SSL
    SSL_CTX *tls;
#endif
#if defined(WITH_TLS) || defined(WITH_SSL)
    char *tls_cert;
    char *tls_key;
    char *tls_pass;
    char *tls_ciphers;
    char *tls_cafile;
    int tls_verify_depth;
     TRISTATE(tls_accept_expired);
#endif
    u_int debug;
    int rulecount;
    struct io_dns_ctx *idc;
    radixtree_t *dns_tree_ptr[3];	// 0: static, 1-2: dynamic
};

/* All tacacs+ packets have the same header format */

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

    u_char type;
#define TAC_PLUS_AUTHEN_TYPE_ASCII  1
#define TAC_PLUS_AUTHEN_TYPE_PAP    2
#define TAC_PLUS_AUTHEN_TYPE_CHAP   3
#define TAC_PLUS_AUTHEN_TYPE_ARAP   4
#define TAC_PLUS_AUTHEN_TYPE_MSCHAP 5
#define TAC_PLUS_AUTHEN_TYPE_MSCHAPV2 6
#define TAC_PLUS_AUTHEN_TYPE_SSHKEY 8
#define TAC_PLUS_AUTHEN_TYPE_SSHCERT 9

    u_char service;
#define TAC_PLUS_AUTHEN_SVC_LOGIN  1
#define TAC_PLUS_AUTHEN_SVC_ENABLE 2
#define TAC_PLUS_AUTHEN_SVC_PPP    3
#define TAC_PLUS_AUTHEN_SVC_ARAP   4
#define TAC_PLUS_AUTHEN_SVC_PT     5
#define TAC_PLUS_AUTHEN_SVC_RCMD   6
#define TAC_PLUS_AUTHEN_SVC_X25    7
#define TAC_PLUS_AUTHEN_SVC_NASI   8

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
#define TAC_PLUS_AUTHEN_METH_NOT_SET		0x00
#define TAC_PLUS_AUTHEN_METH_NONE			0x01
#define TAC_PLUS_AUTHEN_METH_KRB5			0x02
#define TAC_PLUS_AUTHEN_METH_LINE			0x03
#define TAC_PLUS_AUTHEN_METH_ENABLE			0x04
#define TAC_PLUS_AUTHEN_METH_LOCAL			0x05
#define TAC_PLUS_AUTHEN_METH_TACACSPLUS		0x06
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

#define TAC_AUTHOR_REQ_FIXED_FIELDS_SIZE 8

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
};

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

struct tac_pak {
    struct tac_pak *next;
    ssize_t offset;
    ssize_t length;
    time_t delay_until;
    tac_pak_hdr hdr;
};

typedef struct tac_pak tac_pak;

struct author_data;
struct authen_data;
struct mavis_data;

struct upwdat {
    struct pwdat *passwd[PW_MAVIS + 1];
};

struct log_item;

typedef struct tac_session tac_session;
typedef struct tac_profile tac_profile;

struct tac_session {
    struct context *ctx;
    memlist_t *memlist;
    tac_user *user;
    struct in6_addr nac_address;	/* host byte order */
    char *username;
    size_t username_len;
    char *password;
    char *password_new;
    char *password_bad;
    char *msg;
    size_t msg_len;
    char *user_msg;
    size_t user_msg_len;
    char *nas_port;
    size_t nas_port_len;
    char *nac_address_ascii;
    size_t nac_address_ascii_len;
    char *type;
    size_t type_len;
    char *nac_dns_name;		/* DNS reverse mapping for NAC */
    size_t nac_dns_name_len;
    char *acct_type;
    size_t acct_type_len;
    char *action;
    size_t action_len;
    char *service;
    size_t service_len;
    char *protocol;
    size_t protocol_len;
    char *hint;
    size_t hint_len;
    char *challenge;
    char *motd;
    char *welcome_banner;
    char *msgid;
    size_t msgid_len;
    char *cmdline;
    size_t cmdline_len;
    char *message;		// to the user
    size_t message_len;
    char *authen_action;
    size_t authen_action_len;
    char *authen_type;
    size_t authen_type_len;
    char *authen_service;
    size_t authen_service_len;
    char *authen_method;
    size_t authen_method_len;
    char *rule;
    size_t rule_len;
    char *label;
    size_t label_len;
    u_char arg_cnt;
    u_char *arg_len;
    u_char *argp;
    u_char arg_out_cnt;
    u_char *arg_out_len;
    u_char *argp_out;
    char *result;
    size_t result_len;
    u_int priv_lvl;		/* requested privilege level */
    char privlvl[4];
    int privlvl_len;
    char *ssh_key_hash;
    char *ssh_key_id;
    int session_id;
    time_t session_timeout;
    struct author_data *author_data;
    struct authen_data *authen_data;
    struct mavis_data *mavis_data;
    struct upwdat *passwdp;
    struct pwdat *enable;
    tac_profile *profile;
     BISTATE(nac_address_valid);
     BISTATE(flag_mavis_info);
     BISTATE(flag_mavis_auth);
     BISTATE(flag_chalresp);
     BISTATE(mavis_pending);
     BISTATE(revmap_pending);
     BISTATE(revmap_timedout);
     BISTATE(enable_getuser);
     BISTATE(password_bad_again);
     BISTATE(passwd_mustchange);
     BISTATE(mavisauth_res_valid);
     BISTATE(user_is_session_specific);
     BISTATE(username_rewritten);
     BISTATE(chpass);
    u_int mavisauth_res;
    u_int authfail_delay;
    u_int debug;
    u_char seq_no;		/* seq. no. of last packet exchanged */
    u_char version;
    u_char pak_authen_type;
    u_char pak_authen_method;
    void (*resumefn)(tac_session *);
    char **attrs_m;		/* mandatory */
    char **attrs_o;		/* optional (from NAS) */
    char **attrs_a;		/* add optinal (to NAS) */
    int cnt_m;
    int cnt_o;
    int cnt_a;
    ssize_t in_length;
    enum token attr_dflt;
};

struct user_profile_cache {
    tac_user *user;
    tac_profile *profile;
    time_t valid_until;
    enum token res;
};

struct context {
    int sock;			/* socket for this connection */
    io_context_t *io;
    tac_host *host;
    tac_pak *in;
    tac_pak *out;
    tac_pak *delayed;
    rb_tree_t *pool;		/* memory pool */
    rb_tree_t *sessions;
    rb_tree_t *shellctxcache;
    tac_realm *realm;
    char *nas_dns_name;
    size_t nas_dns_name_len;
    char *nas_address_ascii;
    size_t nas_address_ascii_len;
    struct in6_addr nas_address;	/* host byte order */
    u_char flags;		/* TAC_PLUS_SINGLE_CONNECT_FLAG */
    tac_pak_hdr hdr;
    ssize_t hdroff;
    struct tac_key *key;
    time_t last_io;
#ifdef WITH_TLS
    struct tls *tls;
#endif
#ifdef WITH_SSL
    SSL *tls;
#endif
#if defined(WITH_TLS) || defined(WITH_SSL)
    const char *tls_conn_version;
    size_t tls_conn_version_len;
    const char *tls_conn_cipher;
    size_t tls_conn_cipher_len;
    const char *tls_peer_cert_issuer;
    size_t tls_peer_cert_issuer_len;
    const char *tls_peer_cert_subject;
    size_t tls_peer_cert_subject_len;
    char *tls_conn_cipher_strength;
    size_t tls_conn_cipher_strength_len;
    char *tls_peer_cn;
    size_t tls_peer_cn_len;
    char *tls_psk_identity;
    size_t tls_psk_identity_len;
#endif
    char *proxy_addr_ascii;
    size_t proxy_addr_ascii_len;
    char *peer_addr_ascii;
    size_t peer_addr_ascii_len;
    char *msgid;
    size_t msgid_len;
    char *acct_type;
    size_t acct_type_len;
    char *vrf;
    size_t vrf_len;
#define USER_PROFILE_CACHE_SIZE 8
    struct user_profile_cache user_profile_cache[USER_PROFILE_CACHE_SIZE];
     TRISTATE(cleanup_when_idle);	/* cleanup context when idle */
     BISTATE(unencrypted_flag);	/* not MD5 encryped ? */
     BISTATE(single_connection_flag);	/* single-connection enabled? */
     BISTATE(single_connection_test);	/* single-connection capable, but not telling? */
     BISTATE(single_connection_did_warn);
     BISTATE(dying);
     BISTATE(key_fixed);
     BISTATE(revmap_pending);
     BISTATE(revmap_timedout);
    u_int id;
    u_int bug_compatibility;
    u_int debug;
};

struct logfile;

struct context_logfile {
    int fd;
    io_context_t *io;
    struct buffer *buf;
    char path[PATH_MAX + 1];	/* current log file name */
    pid_t pid;
    int dying;
    struct logfile *lf;
};

void cleanup(struct context *, int);

/* acct.c */
void accounting(tac_session *, tac_pak_hdr *);

/* report.c */
void report_string(tac_session *, int, int, char *, char *, int);
void report_hex(tac_session *, int, int, u_char *, int);
void report(tac_session *, int, int, char *, ...)
    __attribute__((format(printf, 4, 5)));

	/* packet.c */
void send_authen_reply(tac_session *, int, char *, int, u_char *, int, u_char);
void send_authen_error(tac_session *, char *, ...)
    __attribute__((format(printf, 2, 3)));
void send_acct_reply(tac_session *, u_char, char *, char *);
void send_author_reply(tac_session *, u_char, char *, char *, int, char **);

	/* utils.c */
void *mempool_malloc(rb_tree_t *, size_t);
void *mempool_realloc(rb_tree_t *, void *, size_t);
void mempool_free(rb_tree_t *, void *);
char *mempool_strdup(rb_tree_t *, char *);
char *mempool_strndup(rb_tree_t *, u_char *, int);
void mempool_destroy(rb_tree_t *);
rb_tree_t *mempool_create(void);

struct memlist *memlist_create(void);
void *memlist_malloc(memlist_t *, size_t);
void *memlist_realloc(memlist_t *, void *, size_t);
void memlist_destroy(memlist_t *);
char *memlist_strdup(memlist_t *, char *);
char *memlist_strndup(memlist_t *, u_char *, int);
void **memlist_add(memlist_t *, void *);

int tac_exit(int) __attribute__((noreturn));

void log_exec(tac_session *, struct context *, enum token, time_t);
void log_add(struct sym *, rb_tree_t **, char *, tac_realm *);
int logs_flushed(tac_realm *);

	/* dump.c */
char *summarise_outgoing_packet_type(tac_pak_hdr *);
void dump_nas_pak(tac_session *, int);
void dump_tacacs_pak(tac_session *, tac_pak_hdr *);

	/* authen.c */
void authen(tac_session *, tac_pak_hdr *);

	/* author.c */
void author(tac_session *, tac_pak_hdr *);

	/* config.c */
int cfg_get_enable(tac_session *, struct pwdat **);

void parse_decls(struct sym *);
void parse_user_final(tac_user *);
int parse_user_profile_fmt(struct sym *, tac_user *, char *, ...);

void parse_log(struct sym *, tac_realm *);
char *eval_log_format(tac_session *, struct context *, struct logfile *, struct log_item *, time_t, size_t *);
struct log_item *parse_log_format_inline(char *, char *, int);

tac_user *new_user(char *, enum token, tac_realm *);
int compare_user(const void *, const void *);
void free_user(tac_user *);
void cfg_init(void);
enum token tac_keycode(char *);
struct upwdat *eval_passwd_acl(tac_session *);
enum token eval_ruleset(tac_session *, tac_realm *);

#ifdef WITH_PCRE2
void tac_rewrite_user(tac_session *, tac_rewrite *);
#else
#define tac_rewrite_user(A,B) /**/
#endif
static __inline__ int minimum(int a, int b)
{
    return (a < b) ? a : b;
}

void tac_read(struct context *, int);
void tac_write(struct context *, int);

void cleanup_session(tac_session *);
struct log_item *parse_log_format(struct sym *);

void mavis_lookup(tac_session *, void (*)(tac_session *), char *, enum pw_ix);
tac_user *lookup_user(char *, tac_realm *);
mavis_ctx *lookup_mcx(tac_realm *);
tac_realm *lookup_realm(char *, tac_realm *);
radixtree_t *lookup_hosttree(tac_realm *);

#define LOG_ACCESS 0x80000000

void get_revmap_nac(tac_session *);
void get_revmap_nas(tac_session *);
void add_revmap(tac_realm *, struct in6_addr *, char *);
void resume_session(tac_session *, int);
void get_pkt_data(tac_session *, struct authen_start *, struct author *);

enum token tac_script_eval_r(tac_session *, struct tac_script_action *);
void tac_script_expire_exec_context(struct context *);
void tac_script_set_exec_context(tac_session *, char *, char *, char *);
char *tac_script_get_exec_context(tac_session *, char *, char *);
enum token eval_tac_acl(tac_session *, struct tac_acl *);
tac_host *lookup_host(char *, tac_realm *);

int query_mavis_info(tac_session *, void (*)(tac_session *), enum pw_ix);
void expire_dynamic_users(tac_realm *);
void drop_mcx(tac_realm *);
void init_mcx(tac_realm *);
void complete_host(tac_host *);
void complete_realm(tac_realm *);

enum token validate_ssh_hash(tac_session *, char *, char **);
enum token validate_ssh_key_id(tac_session *);

extern struct config config;
extern int die_when_idle;

#define CLIENT_BUG_INVALID_START_DATA	0x01
#define CLIENT_BUG_BAD_VERSION		0x02

#endif				/* __HEADERS_H_ */
/*
 * vim:ts=4
 */

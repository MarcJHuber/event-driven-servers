/*
   Copyright (C) 1999-2016 Marc Huber (Marc.Huber@web.de)

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

struct context;
struct acl_element;
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
    int type;			/* S_clear/S_crypt/S_opie/S_deny */
    char value[1];
};

#define TRISTATE_DUNNO	0
#define TRISTATE_YES	1
#define TRISTATE_NO		2
#define BISTATE_YES	1
#define BISTATE_NO	0
#define BISTATE(A) u_int A:1
#define TRISTATE(A) u_int A:2

struct tac_key {
    struct tac_key *next;
    int len;
    time_t warn;
    char key[1];
};

typedef struct {
    u_int line;			/* configuration file line number */
     TRISTATE(valid_for_nas);
     TRISTATE(valid_for_nac);
     TRISTATE(anon_enable);	/* permit anonymous enable */
     TRISTATE(lookup_revmap);	/* lookup reverse mapping in DNS */
     TRISTATE(cleanup_when_idle);	/* may cleanup context when idle */
     TRISTATE(authfallback);	/* authentication fallback permitted? */
     TRISTATE(single_connection);	/* single-connection permitted? */
     TRISTATE(augmented_enable);	/* one-step enable for $enab.* user */
     TRISTATE(map_pap_to_login);
     TRISTATE(authz_if_authc);
     BISTATE(orphan);		/* don't inherit stuff */
    u_int bug_compatibility;
    char *name;			/* host name */
    struct tac_key *key;
    char *motd;
    char *welcome_banner;	/* prompt */
    char *welcome_banner_fallback;	/* fallback prompt */
    char *reject_banner;
    char *authfail_banner;
    char *username;		/* default user name */
    char *groupname;		/* default group for users not in any group */
#ifdef SUPPORT_FOLLOW
    char *follow;		/* alternate daemon */
#endif
    struct pwdat *enable[TAC_PLUS_PRIV_LVL_MAX + 1];	/* enable passwords */
    char enable_implied[TAC_PLUS_PRIV_LVL_MAX + 1];
    radixtree_t *addrtree;
    int authen_max_attempts;
    int authfail_delay;
    int timeout;		/* tcp connection idle timeout */
    int dns_timeout;
    struct tac_acllist *access_acl;
    tac_realm *realm;
    tac_realm *nac_realm;
    tac_realm *aaa_realm;
    tac_rewrite *rewrite_user;
    u_int client_bug;
    u_int debug;
} tac_host;

enum pw_ix { PW_LOGIN = 0, PW_PAP,
#ifdef SUPPORT_ARAP
    PW_ARAP,
#endif
#ifdef SUPPORT_OPAP
    PW_OPAP,
#endif
    PW_CHAP, PW_MSCHAP, PW_MAVIS
};


enum hint_enum { hint_failed =
	0, hint_denied, hint_nopass, hint_expired, hint_default, hint_rejected, hint_delegated, hint_succeeded, hint_permitted, hint_no_cleartext,
    hint_backend_error, hint_denied_profile, hint_failed_password_retry, hint_bug, hint_abort, hint_denied_by_acl, hint_bad_nas, hint_bad_nac,
    hint_invalid_challenge_length, hint_weak_password, hint_max
};

struct stringlist;

/* A user or group definition. */
typedef struct {
    char *msg;			/* message for this user */
    u_int line;			/* line number defined on */
    time_t valid_from;		/* validity period start */
    time_t valid_until;		/* validity period end */
    time_t dynamic;		/* caching timeout. Always 0 for static users */
    char enable_implied[TAC_PLUS_PRIV_LVL_MAX + 1];
    enum token svc_dflt;	/* default authorization for svc or cmd */
    radixtree_t *nac_range;	/* valid NAC addresses */
    radixtree_t *nas_range;	/* valid NAS addresses */
    struct stringlist *nas_limit_dflt;	/* group valid for given NAS list only */
    struct acl_element *nac_regex;	/* regular expressions for NON-IP NAC names */
    struct tac_acllist *acllist;
    struct tac_acllist *nas_member_acl;	/* NAS specific group membership */
    struct tac_acllist *tag_acl;
    struct tac_acllist *passwd_acllist;
    struct pwdat *enable[TAC_PLUS_PRIV_LVL_MAX + 1];	/* enable passwords */
    rb_tree_t *svcs;		/* services */
    rb_tree_t *svc_prohibit;	/* prohibited services */
    mem_t *mem;		/* memory pool */
    tac_realm *realm;
    tac_realm *mavis_realm;	/* for local users only */
    u_int debug;		/* debug flags */
     TRISTATE(chalresp);
     TRISTATE(hushlogin);
     BISTATE(passwd_oneshot);
     BISTATE(fallback_only);
    char name[1];		/* username */
} tac_user;

struct config {
    uid_t userid;		/* run as this user */
    gid_t groupid;		/* run as this group */
    mode_t mask;		/* file mask */
    char *hostname;
    int retire;			/* die after <retire> invocations */
    time_t suicide;		/* when to commit suicide */
    int dns_caching_period;
    char *c7xlat;		/* cisco 7 key */
    size_t c7xlat_len;		/* cisco 7 key length, should be 53 */
    tac_realm *top_realm;	/* actually the one called "default" */
    tac_realm *default_realm;
    rb_tree_t *realms;
    rb_tree_t *logfiles;
    int log_matched_group:1;
    int haproxy:1;
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

struct realm {
    char *name;
    rb_tree_t *acct;
    rb_tree_t *access;
    rb_tree_t *author;
    struct tac_key *key;
    radixtree_t *hosttree;
    rb_tree_t *usertable;
    rb_tree_t *grouptable;
    rb_tree_t *logfile_templates;
    rb_tree_t *rewrite;
    mavis_ctx *mcx;

     BISTATE(acct_inherited);
     BISTATE(access_inherited);
     BISTATE(author_inherited);
     BISTATE(key_inherited);
     BISTATE(mcx_inherited);
     BISTATE(pap_login);

     TRISTATE(anon_enable);	/* permit anonymous enable */
     TRISTATE(lookup_revmap);	/* lookup reverse mapping in DNS */
     TRISTATE(augmented_enable);	/* permit one-step enable */
     TRISTATE(authfallback);
     TRISTATE(single_connection);
     TRISTATE(cleanup_when_idle);
     TRISTATE(map_pap_to_login);

     BISTATE(chalresp);		/* enable challenge-response authentication */
     BISTATE(chalresp_noecho);	/* enable local echo for response */
     BISTATE(chpass);		/* enable password change dialogue */
     BISTATE(mavis_userdb);	/* use MAVIS for user authentication, too */
     BISTATE(mavis_noauthcache);	/* don't do backend password caching */
     BISTATE(mavis_pap);
     BISTATE(mavis_login);
     BISTATE(mavis_pap_prefetch);
     BISTATE(mavis_login_prefetch);
     BISTATE(skip_missing_groups);
     BISTATE(skip_conflicting_groups);

    char separator;		/* tag separator for group preference */
    int caching_period;		/* user caching period */
    int warning_period;		/* password expiration warning period */
    int timeout;		/* tcp connection idle timeout */
    int dns_timeout;
    int session_timeout;	/* session idle timeout */
    int backend_failure_period;
    int authen_max_attempts;
    int authfail_delay;
    char *date_format;
    char *log_separator;
    size_t log_separator_len;
    struct tac_acl *mavis_user_acl;
    int mavis_user_acl_negate;
    struct tac_acl *enable_user_acl;
    struct tac_acl *password_acl;
    int password_acl_negate;
    time_t shellctx_expire;
    time_t last_backend_failure;
    tac_realm *aaa_realm;
    tac_realm *group_realm;
    tac_realm *nac_realm;
#ifdef WITH_PCRE2
    pcre2_code *password_minimum_requirement;
#endif
    u_int debug;
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

typedef struct tac_session tac_session;

struct tac_session {
    struct context *ctx;
    mem_t *mem;
    tac_user *user;
    struct in6_addr nac_address;	/* host byte order */
    char *username;
    char *username_default;
    char *groupname_default;
    char *final_match;
    char *tag;			/* group membership selector */
    char *password;
    char *password_new;
    char *password_bad;
    char *user_msg;
    char *nas_port;
    char *nac_address_ascii;
    char *nac_dns_name;		/* DNS reverse mapping for NAC */
    char *challenge;
    char *motd;
    char *welcome_banner;
    int priv_lvl;		/* requested privilege level */
    int session_id;
    time_t timeout;
    int dns_timeout;
    struct author_data *author_data;
    struct authen_data *authen_data;
    struct mavis_data *mavis_data;
    struct upwdat *passwdp;
    struct pwdat *enable;
    struct tac_acl_cache *tac_acl_cache;
    tac_realm *mavis_realm;
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
     BISTATE(user_is_session_specific);
     BISTATE(username_rewritten);
    u_int bug_compatibility;
    u_int mavisauth_res;
    u_int client_bug;
    u_int debug;
    u_char seq_no;		/* seq. no. of last packet exchanged */
    u_char version;
    u_char authen_type;
    u_char authen_method;
    void (*resumefn)(tac_session *);
};

struct context {
    int sock;			/* socket for this connection */
    io_context_t *io;
    tac_host **hostchain;
    tac_pak *in;
    tac_pak *out;
    tac_pak *delayed;
    mem_t *mem;		/* memory pool */
    rb_tree_t *sessions;
    rb_tree_t *shellctxcache;
    tac_realm *aaa_realm;
    tac_realm *nac_realm;
    tac_realm *realm;
    tac_rewrite *rewrite_user;
    char *nas_dns_name;
    char *nas_address_ascii;
    struct in6_addr nas_address;	/* host byte order */
    u_char flags;		/* TAC_PLUS_SINGLE_CONNECT_FLAG */
    tac_pak_hdr hdr;
    ssize_t hdroff;
    struct tac_key *key;
    char *motd;
    char *welcome_banner;
    char *welcome_banner_fallback;
    char *reject_banner;
    char *authfail_banner;
    struct pwdat *enable[TAC_PLUS_PRIV_LVL_MAX + 1];	/* enable passwords */
    int authen_max_attempts;
    int authfail_delay;
    time_t last_io;
     TRISTATE(anon_enable);	/* anonymous enable */
     TRISTATE(augmented_enable);	/* augmented enable */
     TRISTATE(authfallback);	/* authentication fallback permitted? */
     TRISTATE(single_connection);	/* single-connection permitted by configuration? */
     TRISTATE(cleanup_when_idle);	/* cleanup context when idle */
     TRISTATE(lookup_revmap);	/* lookup reverse mapping in DNS */
     TRISTATE(map_pap_to_login);
     BISTATE(authz_if_authc);
     BISTATE(single_connection_flag);	/* single-connection enabled? */
     BISTATE(single_connection_test);	/* single-connection capable, but not telling? */
     BISTATE(single_connection_did_warn);
     BISTATE(dying);
     BISTATE(key_fixed);
     BISTATE(revmap_pending);
     BISTATE(revmap_timedout);
    int timeout;		/* tcp connection idle timeout */
    int dns_timeout;
    u_int id;
    u_int debug;
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
int tac_exit(int) __attribute__((noreturn));

void log_start(rb_tree_t *, char *, char *);
void log_write(rb_tree_t *, char *, size_t);
void log_flush(rb_tree_t *);
void log_write_separator(rb_tree_t *);
void log_add(rb_tree_t **, char *, tac_realm *);
int logs_flushed(void);
int compare_log(const void *, const void *);

/* dump.c */
char *summarise_outgoing_packet_type(tac_pak_hdr *);
void dump_nas_pak(tac_session *, int);
void dump_tacacs_pak(tac_session *, tac_pak_hdr *);

/* authen.c */
void authen(tac_session *, tac_pak_hdr *);

/* author.c */
void author(tac_session *, tac_pak_hdr *);

/* config.c */
int cfg_get_access_acl(tac_session *, enum hint_enum *);
int cfg_get_enable(tac_session *, struct pwdat **);
int cfg_get_message(tac_session *, char **);
int cfg_get_hushlogin(tac_session *);
enum token cfg_get_cmd_node(tac_session *, char *, char *, char **);
enum token cfg_get_svc_attrs(tac_session *, enum token, char *, char *, rb_tree_t *, rb_tree_t *, rb_tree_t *, rb_tree_t *, rb_tree_t *, rb_tree_t *,
			     enum token *, enum token *);

int cfg_get_debug(tac_session *, u_int *);
int cfg_get_client_bug(tac_session *, u_int *);
int cfg_get_access(tac_session *, enum hint_enum *);
int cfg_get_access_nas(tac_session *, enum hint_enum *);
int cfg_get_access_nac(tac_session *, enum hint_enum *);
tac_realm *cfg_get_mavis_realm(tac_session *);

void parse_decls(struct sym *);
void parse_user_final(tac_user *);
int parse_user_profile(struct sym *, tac_user *);
int parse_user_profile_fmt(struct sym *, tac_user *, char *, ...)
    __attribute__((format(printf, 3, 4)));
void parse_log(struct sym *, tac_realm *);
tac_user *new_user(char *, enum token, tac_realm *);
void free_user(tac_user *);
void cfg_init(void);
enum token tac_keycode(char *);
char *eval_taglist(tac_session *, tac_user *);
void set_taglist(tac_session *);
enum token eval_host_acl(tac_session *);
struct upwdat *eval_passwd_acl(tac_session *);
#ifdef WITH_PCRE2
void tac_rewrite_user(tac_session *);
#else
#define tac_rewrite_user(A) /**/
#endif
static __inline__ int minimum(int a, int b)
{
    return (a < b) ? a : b;
}

void tac_read(struct context *, int);
void tac_write(struct context *, int);

void cleanup_session(tac_session *);

void mavis_lookup(tac_session *, void (*)(tac_session *), char *, enum pw_ix);
tac_user *lookup_user(rb_tree_t *, char *);

#define LOG_ACCESS 0x80000000

#ifdef WITH_DNS
struct io_dns_ctx;
#endif

void get_revmap_nac(tac_session *, tac_host **, int, int);
void get_revmap_nas(struct context *);
void add_revmap(struct in6_addr *, char *);
void resume_session(tac_session *, int);

void tac_script_expire_exec_context(struct context *);
void tac_script_set_exec_context(tac_session *, char *, char *, char *);
char *tac_script_get_exec_context(tac_session *, char *, char *);
enum token eval_tac_acl(tac_session *, char *, struct tac_acl *);

int query_mavis_info(tac_session *, void (*)(tac_session *), enum pw_ix);
void expire_dynamic_users(void);
void drop_mcx(void);
void init_mcx(void);
tac_realm *get_realm(char *);

#ifdef WITH_DNS
extern struct io_dns_ctx *idc;
extern radixtree_t *dns_tree_ptr_dynamic[2];
#endif
extern radixtree_t *dns_tree_ptr_static;
extern struct config config;
extern int die_when_idle;

#endif				/* __HEADERS_H_ */

#define CLIENT_BUG_INVALID_START_DATA	0x01
#define CLIENT_BUG_BAD_VERSION			0x02

/*
 * vim:ts=4
 */

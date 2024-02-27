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
#include "misc/version.h"
#include "misc/strops.h"
#include <setjmp.h>
#include <pwd.h>
#include <grp.h>
#include <sys/utsname.h>

#include <glob.h>
#ifndef GLOB_NOMAGIC
#define GLOB_NOMAGIC 0
#endif
#ifndef GLOB_BRACE
#define GLOB_BRACE 0
#endif
#ifndef GLOB_NOESCAPE
#define GLOB_NOESCAPE 0
#endif

#ifdef WITH_CURL
#include <curl/curl.h>
#endif

#ifdef WITH_PCRE2
#include <pcre2.h>
#endif

#include <regex.h>

static const char rcsid[] __attribute__((used)) = "$Id$";

struct tac_acllist {
    struct tac_acllist *next;
    struct tac_acl *acl;
    u_int negate:1;
    union {
	enum token token;
	radixtree_t *rt;
	char *tag;
	struct upwdat *passwdp;
    } u;
};

struct in6_cidr {
    struct in6_addr addr;
    int mask;
};

enum tac_acl_type { T_cidr = 0, T_host, T_regex_posix, T_regex_pcre, T_dns_regex_posix,
    T_dns_regex_pcre, T_realm
};

struct acl_element {
    struct acl_element *next;
    char *string;
    enum tac_acl_type type;
    u_int negate:1;
    u_int line:16;
    union {
	tac_host *h;
	tac_realm *m;
	struct in6_cidr *c;
	struct mavis_timespec *t;
	struct tac_acl *a;
	regex_t *r;
#ifdef WITH_PCRE2
	pcre2_code *p;
#endif
    } blob;
};

struct tac_acl_expr {
    struct acl_element *acl, *nac, *nas, *port, *time, *realm;
    u_int negate:1;
    struct tac_acl_expr *next;
};

struct tac_acl {
    struct mavis_action *action;
    struct tac_acl_expr *expr;
    char name[1];
};

struct stringlist {
    struct stringlist *next;
    char s[1];
};

struct node_perm {
    enum token type;		/* node type */
    u_int line;			/* line number declared on */
    enum tac_acl_type regex_type;
    struct node_perm *next;
    void *regex;		/* node value */
    char name[1];		/* node name */
};

struct node_cmd {
    enum token type;		/* node type */
    u_int line;			/* line number declared on */
    struct node_perm *perm;
    char *msg_deny;
    char *msg_permit;
    char *msg_debug;
    char name[1];		/* node name */
};

struct node_svc {
    enum token type;		/* node type */
    u_int line;			/* line number declared on */
    char **attrs_m;		/* mandatory */
    char **attrs_o;		/* optional (from NAS) */
    char **attrs_a;		/* add optinal (to NAS) */
    int cnt_m;
    int cnt_o;
    int cnt_a;
    struct tac_acllist *acllist;
    enum token sub_dflt;	/* default for child nodes */
    enum token attr_dflt;	/* default for attributes */
    rb_tree_t *sub;		/* For svc: cmds or protocols */
    char *msg_deny;
    char *msg_permit;
    char *msg_debug;
    struct mavis_action *script;
    struct tac_acl *acl;
    u_int negate:1;		/* ... acl */
    u_int final:1;
    struct node_svc *next;
    char name[1];
};

static rb_tree_t *hosttable = NULL;
static rb_tree_t *acltable = NULL;

static void parse_host(struct sym *, tac_realm *);
static void parse_user(struct sym *, tac_realm *);
static void parse_user_attr(struct sym *, tac_user *, enum token);
static void parse_attrs(struct sym *, tac_user *, struct node_svc *);
static void parse_cmd_matches(struct sym *, tac_user *, struct node_cmd *);
static void parse_svcs(struct sym *, tac_user *);
static void parse_tag(struct sym *, tac_user *);
static void parse_tac_acl(struct sym *);
static void parse_rewrite(struct sym *, tac_realm *);

static int compare_user(const void *a, const void *b)
{
    return strcmp(((tac_user *) a)->name, ((tac_user *) b)->name);
}

static int compare_rewrite(const void *a, const void *b)
{
    return strcmp(((tac_rewrite *) a)->name, ((tac_rewrite *) b)->name);
}

static int compare_realm(const void *a, const void *b)
{
    return strcmp(((tac_realm *) a)->name, ((tac_realm *) b)->name);
}

static struct tac_acl *tac_acl_lookup(char *);

tac_realm *get_realm(char *name)
{
    tac_realm *r;
    rb_node_t *rbn;

    if (!name || !*name)
	name = "default";

    r = alloca(sizeof(tac_realm));
    r->name = name;
    if ((rbn = RB_search(config.realms, r)))
	return RB_payload(rbn, tac_realm *);

    r = calloc(1, sizeof(tac_realm));
    if (config.default_realm) {
	memcpy(r, config.default_realm, sizeof(tac_realm));
	r->acct_inherited = BISTATE_YES;
	r->access_inherited = BISTATE_YES;
	r->author_inherited = BISTATE_YES;
	r->key_inherited = BISTATE_YES;
	r->mcx_inherited = BISTATE_YES;
    }

    r->name = strdup(name);
    r->hosttree = radix_new(NULL, NULL);
    r->usertable = RB_tree_new(compare_user, (void (*)(void *)) free_user);
    r->grouptable = RB_tree_new(compare_user, NULL);
    r->rewrite = RB_tree_new(compare_rewrite, NULL);

    RB_insert(config.realms, r);

    r->group_realm = get_realm("default");

    if (!tac_acl_lookup("__internal__username_acl__")) {
	char *acl = "acl script = __internal__username_acl__ { if (user =~ \"[]<>/()|=[*\\\"':$]+\") deny permit }\n";
	struct sym sym;
	memset(&sym, 0, sizeof(sym));
	sym.filename = "__internal__";
	sym.line = 1;
	sym.in = sym.tin = acl;
	sym.len = sym.tlen = strlen(acl);
	sym_init(&sym);
	parse_tac_acl(&sym);
    }
    r->mavis_user_acl = tac_acl_lookup("__internal__username_acl__");

    return r;
}

void init_mcx(void)
{
    rb_node_t *rbn;
    for (rbn = RB_first(config.realms); rbn; rbn = RB_next(rbn)) {
	tac_realm *r = RB_payload(rbn, tac_realm *);
	if (r->mcx && (r->mcx_inherited == BISTATE_NO))
	    mavis_init(r->mcx, MAVIS_API_VERSION);
    }
}

void drop_mcx(void)
{
    rb_node_t *rbn;
    for (rbn = RB_first(config.realms); rbn; rbn = RB_next(rbn)) {
	tac_realm *r = RB_payload(rbn, tac_realm *);
	if (r->mcx && (r->mcx_inherited == BISTATE_NO))
	    mavis_drop(r->mcx);
    }
}

static void expire_dynamic_users_by_realm(tac_realm * r)
{
    rb_node_t *rbn, *rbnext;
    for (rbn = RB_first(r->usertable); rbn; rbn = rbnext) {
	time_t v = RB_payload(rbn, tac_user *)->dynamic;
	rbnext = RB_next(rbn);

	if (v && v < io_now.tv_sec)
	    RB_delete(r->usertable, rbn);
    }
}

void expire_dynamic_users(void)
{
    rb_node_t *rbn;
    for (rbn = RB_first(config.realms); rbn; rbn = RB_next(rbn))
	expire_dynamic_users_by_realm(RB_payload(rbn, tac_realm *));
}

tac_user *lookup_user(rb_tree_t * rbt, char *username)
{
    rb_node_t *rbn;
    tac_user *user = alloca(sizeof(tac_user) + strlen(username));
    strcpy(user->name, username);
    if ((rbn = RB_search(rbt, user))) {
	user = RB_payload(rbn, tac_user *);
	if (user->dynamic && (user->dynamic < io_now.tv_sec)) {
	    RB_delete(user->realm->usertable, rbn);
	    user = NULL;
	}
    } else
	user = NULL;
    return user;
}

static int compare_host(const void *a, const void *b)
{
    return strcmp(((tac_host *) a)->name, ((tac_host *) b)->name);
}

static int compare_acl(const void *a, const void *b)
{
    return strcmp(((struct tac_acl *) a)->name, ((struct tac_acl *) b)->name);
}

static void free_svc(struct node_svc *n)
{
    if (n->sub)
	RB_tree_delete(n->sub);
}

static int compare_cmd(const void *a, const void *b)
{
    return strcmp(((struct node_cmd *) a)->name, ((struct node_cmd *) b)->name);
}

static int compare_svc(const void *a, const void *b)
{
    if (((struct node_svc *) a)->type < ((struct node_svc *) b)->type)
	return -1;
    if (((struct node_svc *) a)->type > ((struct node_svc *) b)->type)
	return +1;

    return strcmp(((struct node_svc *) a)->name, ((struct node_svc *) b)->name);
}

static struct sym *globerror_sym = NULL;

static int globerror(const char *epath, int eerrno)
{
    report_cfg_error(LOG_ERR, ~0, "%s:%u: glob(%s): %s", globerror_sym->filename, globerror_sym->line, epath, strerror(eerrno));
    return 0;
}

static void tac_sym_get(struct sym *sym)
{
    sym_get(sym);
    switch (sym->code) {
    case S_router:
	sym->code = S_nas;
	return;
    case S_profile:
	sym->code = S_member;
	return;
    case S_exec:
	sym->code = S_shell;
	return;
    case S_trace:
	sym->code = S_debug;
	return;
    default:
	return;
    }
}

static time_t parse_date(struct sym *sym, time_t offset);

static void parse_key(struct sym *sym, struct tac_key **tk)
{
    int keylen;
    time_t warn = 0;

    tac_sym_get(sym);
    if (sym->code == S_warn) {
	tac_sym_get(sym);
	if (sym->code == S_equal)
	    warn = io_now.tv_sec - 1;
	else
	    warn = parse_date(sym, 0);
    }

    while (*tk)
	tk = &(*tk)->next;

    parse(sym, S_equal);
    keylen = strlen(sym->buf);

    *tk = calloc(1, sizeof(struct tac_key) + keylen);
    (*tk)->warn = warn;
    (*tk)->len = keylen;
    strncpy((*tk)->key, sym->buf, keylen);

    tac_sym_get(sym);
}

struct dns_forward_mapping {
    struct dns_forward_mapping *next;
    struct in6_addr a;
    char *name;
};

static int compare_dns_tree_a(const void *a, const void *b)
{
    return strcmp(((struct dns_forward_mapping *) a)->name, ((struct dns_forward_mapping *) b)->name);
}

static rb_tree_t *dns_tree_a = NULL;

static void dns_add_a(rb_tree_t ** t, struct in6_addr *a, char *name)
{
    struct dns_forward_mapping *ds, *dn = calloc(1, sizeof(struct dns_forward_mapping));
    struct dns_forward_mapping **dsp = &ds;

    if (!*t)
	*t = RB_tree_new(compare_dns_tree_a, NULL);

    dn->name = name;
    ds = (struct dns_forward_mapping *) RB_lookup(dns_tree_a, dn);
    if (ds) {
	while (*dsp) {
	    if (!memcmp(&(*dsp)->a, a, sizeof(struct in6_addr))) {
		free(dn);
		return;
	    }
	    dsp = &(*dsp)->next;
	}
	*dsp = dn;
	dn->name = ds->name;
	dn->a = *a;
	return;
    }
    dn->a = *a;
    dn->name = strdup(name);
    RB_insert(dns_tree_a, dn);
}

static struct dns_forward_mapping *dns_lookup_a(rb_tree_t * t, char *name)
{
    struct dns_forward_mapping dn;

    if (!t)
	return NULL;

    dn.name = name;
    return (struct dns_forward_mapping *) RB_lookup(dns_tree_a, &dn);
}

static void parse_etc_hosts(char *url)
{
    struct sym sym;
    char *buf;
    int bufsize;

    memset(&sym, 0, sizeof(sym));
    sym.filename = url;
    sym.line = 1;

    sym.env_valid = 1;
    if (setjmp(sym.env))
	tac_exit(EX_CONFIG);

    if (cfg_open_and_read(url, &buf, &bufsize)) {
	report_cfg_error(LOG_ERR, ~0, "Couldn't open %s: %s", url, strerror(errno));
	return;
    }

    sym.tlen = sym.len = bufsize;
    sym.tin = sym.in = buf;

    sym_init(&sym);

    while (sym.code != S_eof) {
	struct in6_addr a;
	int cm;
	u_int line = sym.line;

	if (!v6_ptoh(&a, &cm, sym.buf)) {
	    tac_sym_get(&sym);
	    if (sym.line != line)
		continue;
	    radix_add(dns_tree_ptr_static, &a, cm, strdup(sym.buf));
	}

	do {
	    dns_add_a(&dns_tree_a, &a, sym.buf);
	    tac_sym_get(&sym);
	}
	while (sym.code != S_eof && sym.line == line);
    }

    cfg_close(url, buf, bufsize);
}

#define parse_tristate(A) (parse_bool(A) ? TRISTATE_YES : TRISTATE_NO);
#define parse_bistate(A) (parse_bool(A) ? BISTATE_YES : BISTATE_NO);

static void top_only(struct sym *sym, tac_realm * r)
{
    if (r != config.default_realm)
	parse_error(sym, "Directive not available at realm level.");
}

static rb_tree_t *timespectable = NULL;

void parse_decls_real(struct sym *sym, tac_realm * r)
{
    /* Top level of parser */
    while (1)
	switch (sym->code) {
	case S_closebra:
	case S_eof:
	    fflush(stderr);
	    return;
	case S_password:
	    tac_sym_get(sym);
	    switch (sym->code) {
	    case S_maxattempts:
		tac_sym_get(sym);
		parse(sym, S_equal);
		r->authen_max_attempts = parse_int(sym);
		continue;
	    case S_backoff:
		tac_sym_get(sym);
		parse(sym, S_equal);
		r->authfail_delay = parse_seconds(sym);
		continue;
	    case S_acl:
		tac_sym_get(sym);
		parse(sym, S_equal);
		if (sym->code == S_not) {
		    r->password_acl_negate = BISTATE_YES;
		    tac_sym_get(sym);
		}
		r->password_acl = tac_acl_lookup(sym->buf);
		if (!r->password_acl)
		    parse_error(sym, "ACL '%s' not found)", sym->buf);
		tac_sym_get(sym);
		continue;
	    default:
		parse_error_expect(sym, S_acl, S_maxattempts, S_backoff, S_unknown);
	    }
	case S_pap:
	    tac_sym_get(sym);
	    switch (sym->code) {
	    case S_backend:
		tac_sym_get(sym);
		parse(sym, S_equal);
		parse(sym, S_mavis);
		if (sym->code == S_prefetch) {
		    tac_sym_get(sym);
		    r->mavis_pap_prefetch = BISTATE_YES;
		}
		r->mavis_pap = BISTATE_YES;
		r->mavis_userdb = BISTATE_YES;
		break;
	    case S_password:
		tac_sym_get(sym);
		switch (sym->code) {
		case S_default:
		    tac_sym_get(sym);
		case S_equal:
		    parse(sym, S_equal);
		    switch (sym->code) {
		    case S_pap:
			r->pap_login = BISTATE_NO;
			break;
		    case S_login:
			r->pap_login = BISTATE_YES;
			break;
		    default:
			parse_error_expect(sym, S_login, S_pap, S_unknown);
		    }
		    tac_sym_get(sym);
		    continue;
		case S_mapping:
		    tac_sym_get(sym);
		    parse(sym, S_equal);
		    switch (sym->code) {
		    case S_pap:
			r->map_pap_to_login = TRISTATE_NO;
			break;
		    case S_login:
			r->map_pap_to_login = TRISTATE_YES;
			break;
		    default:
			parse_error_expect(sym, S_login, S_pap, S_unknown);
		    }
		    tac_sym_get(sym);
		    continue;
		default:
		    parse_error_expect(sym, S_default, S_equal, S_mapping, S_unknown);
		}
	    default:
		parse_error_expect(sym, S_backend, S_login, S_unknown);
	    }
	    continue;
	case S_login:
	    tac_sym_get(sym);
	    parse(sym, S_backend);
	    parse(sym, S_equal);
	    parse(sym, S_mavis);
	    while (1) {
		switch (sym->code) {
		case S_prefetch:
		    tac_sym_get(sym);
		    r->mavis_login_prefetch = TRISTATE_YES;
		    continue;
		case S_chalresp:
		    tac_sym_get(sym);
		    r->chalresp = TRISTATE_YES;
		    if (sym->code == S_noecho) {
			tac_sym_get(sym);
			r->chalresp_noecho = TRISTATE_YES;
		    }
		    continue;
		case S_chpass:
		    tac_sym_get(sym);
		    r->chpass = BISTATE_YES;
		    continue;
		default:;
		}
		break;
	    }
	    r->mavis_login = BISTATE_YES;
	    r->mavis_userdb = BISTATE_YES;
	    continue;
	case S_working:	// deprecate?
	    top_only(sym, r);
	    tac_sym_get(sym);
	    parse(sym, S_directory);
	    tac_sym_get(sym);
	    parse(sym, S_equal);
	    if (chdir(sym->buf))
		parse_error(sym, "chdir(%s): %s", sym->buf, strerror(errno));
	    tac_sym_get(sym);
	    continue;
	case S_accounting:
	    tac_sym_get(sym);
	    parse(sym, S_log);
	    parse(sym, S_equal);
	    if (r->acct_inherited == BISTATE_YES)
		r->acct = NULL, r->acct_inherited = BISTATE_NO;
	    log_add(&r->acct, sym->buf, r);
	    tac_sym_get(sym);
	    continue;
	case S_access:
	    tac_sym_get(sym);
	    parse(sym, S_log);
	    parse(sym, S_equal);
	    if (r->access_inherited == BISTATE_YES)
		r->access = NULL, r->access_inherited = BISTATE_NO;
	    log_add(&r->access, sym->buf, r);
	    tac_sym_get(sym);
	    continue;
	case S_authorization:
	    tac_sym_get(sym);
	    parse(sym, S_log);
	    switch (sym->code) {
	    case S_group:
		tac_sym_get(sym);
		parse(sym, S_equal);
		config.log_matched_group = parse_bool(sym) ? 1 : 0;
		continue;
	    case S_equal:
		tac_sym_get(sym);
		break;
	    default:
		parse_error_expect(sym, S_equal, S_group, S_unknown);
	    }
	    if (r->author_inherited == BISTATE_YES)
		r->author = NULL, r->author_inherited = BISTATE_NO;
	    log_add(&r->author, sym->buf, r);
	    tac_sym_get(sym);
	    continue;
	case S_authentication:
	    tac_sym_get(sym);
	    switch (sym->code) {
	    case S_log:	// identical to access log
		tac_sym_get(sym);
		parse(sym, S_equal);
		if (r->access_inherited == BISTATE_YES)
		    r->access = NULL, r->access_inherited = BISTATE_NO;
		log_add(&r->access, sym->buf, r);
		tac_sym_get(sym);
		continue;
	    case S_fallback:
		tac_sym_get(sym);
		switch (sym->code) {
		case S_equal:
		    tac_sym_get(sym);
		    r->authfallback = parse_tristate(sym);
		    break;
		case S_period:
		    tac_sym_get(sym);
		    parse(sym, S_equal);
		    r->backend_failure_period = parse_seconds(sym);
		    break;
		default:
		    parse_error_expect(sym, S_equal, S_period, S_unknown);
		}
		continue;
	    case S_realm:
		tac_sym_get(sym);
		parse(sym, S_equal);
		r->aaa_realm = get_realm(sym->buf);
		tac_sym_get(sym);
		break;
	    default:
		parse_error_expect(sym, S_log, S_authentication, S_unknown);
	    }
	    continue;
	case S_aaa:
	    tac_sym_get(sym);
	    parse(sym, S_realm);
	    parse(sym, S_equal);
	    r->aaa_realm = get_realm(sym->buf);
	    tac_sym_get(sym);
	    continue;
	case S_default:
	    top_only(sym, r);
	    tac_sym_get(sym);
	    parse(sym, S_realm);
	    parse(sym, S_equal);
	    config.default_realm = get_realm(sym->buf);
	    tac_sym_get(sym);
	    continue;
	case S_key:
	    report(NULL, LOG_ERR, ~0, "%s:%u: \"key\" keyword is deprecated at top " "configuration level.", sym->filename, sym->line);
	    if (r->key_inherited)
		r->key = NULL, r->key_inherited = BISTATE_NO;
	    parse_key(sym, &r->key);
	    continue;
	case S_singleconnection:
	    tac_sym_get(sym);
	    switch (sym->code) {
	    case S_mayclose:
		tac_sym_get(sym);
		parse(sym, S_equal);
		r->cleanup_when_idle = parse_tristate(sym);
		break;
	    case S_equal:
		tac_sym_get(sym);
		r->single_connection = parse_tristate(sym);
		break;
	    default:
		parse_error_expect(sym, S_mayclose, S_equal, S_unknown);
	    }
	    continue;
	case S_warning:
	    tac_sym_get(sym);
	    parse(sym, S_period);
	    parse(sym, S_equal);
	    r->warning_period = parse_seconds(sym);
	    if (r->warning_period < 60)
		r->warning_period *= 86400;
	    continue;
	case S_skip:
	    tac_sym_get(sym);
	    switch (sym->code) {
	    case S_missing:
		sym_get(sym);
		parse(sym, S_groups);
		parse(sym, S_equal);
		r->skip_missing_groups = parse_bistate(sym);
		continue;
	    case S_conflicting:
		sym_get(sym);
		parse(sym, S_groups);
		parse(sym, S_equal);
		r->skip_conflicting_groups = parse_bistate(sym);
		continue;
	    default:
		parse_error_expect(sym, S_conflicting, S_missing, S_unknown);
	    }
	case S_connection:
	    tac_sym_get(sym);
	    parse(sym, S_timeout);
	    parse(sym, S_equal);
	    r->timeout = parse_seconds(sym);
	    continue;
	case S_session:
	    tac_sym_get(sym);
	    parse(sym, S_timeout);
	    parse(sym, S_equal);
	    r->session_timeout = parse_seconds(sym);
	    continue;
	case S_client:
	    tac_sym_get(sym);
	    parse(sym, S_realm);
	    parse(sym, S_equal);
	    r->nac_realm = get_realm(sym->buf);
	    tac_sym_get(sym);
	    continue;
	case S_dns:
	    tac_sym_get(sym);
	    switch (sym->code) {
	    case S_timeout:
		tac_sym_get(sym);
		parse(sym, S_equal);
		r->dns_timeout = parse_seconds(sym);
		continue;
	    case S_reverselookup:
		tac_sym_get(sym);
		parse(sym, S_equal);
		r->lookup_revmap = parse_tristate(sym);
		continue;
	    case S_cleanup:
		top_only(sym, r);
		tac_sym_get(sym);
		parse(sym, S_period);
		parse(sym, S_equal);
		config.dns_caching_period = parse_seconds(sym) / 2;
		continue;
	    case S_preload:
		tac_sym_get(sym);
	    case S_address:
		top_only(sym, r);
		switch (sym->code) {
		case S_file:
		    {
			glob_t globbuf;
			int i;

			tac_sym_get(sym);
			parse(sym, S_equal);
			// dns preload file = /etc/hosts

			memset(&globbuf, 0, sizeof(globbuf));

			globerror_sym = sym;

			switch (glob(sym->buf, GLOB_ERR | GLOB_NOESCAPE | GLOB_NOMAGIC | GLOB_BRACE, globerror, &globbuf)) {
			case 0:
			    for (i = 0; i < (int) globbuf.gl_pathc; i++)
				parse_etc_hosts(globbuf.gl_pathv[i]);
			    break;
#ifdef GLOB_NOMATCH
			case GLOB_NOMATCH:
			    globerror(sym->buf, ENOENT);
			    break;
#endif				/* GLOB_NOMATCH */
			default:
			    parse_etc_hosts(sym->buf);
			    globfree(&globbuf);
			}
			tac_sym_get(sym);
			continue;
		    }
		case S_address:
		    top_only(sym, r);
		    {
			// dns preload address $ip = $name
			struct in6_addr a;
			int cm;

			parse(sym, S_address);

			if (v6_ptoh(&a, &cm, sym->buf))
			    parse_error(sym, "Expected an IP address or network in CIDR " "notation, but got '%s'.", sym->buf);
			tac_sym_get(sym);
			parse(sym, S_equal);

			radix_add(dns_tree_ptr_static, &a, cm, strdup(sym->buf));

			tac_sym_get(sym);
			continue;
		    }
		default:
		    parse_error_expect(sym, S_address, S_file, S_unknown);
		}
	    default:
		parse_error_expect(sym, S_cleanup, S_preload, S_unknown);
	    }
	    continue;
	case S_context:
	    tac_sym_get(sym);
	    parse(sym, S_timeout);
	    parse(sym, S_equal);
	    r->shellctx_expire = parse_seconds(sym);
	    continue;
	case S_cache:
	    tac_sym_get(sym);
	    parse(sym, S_timeout);
	    parse(sym, S_equal);
	    r->caching_period = parse_seconds(sym);
	    continue;
	case S_date:
	    tac_sym_get(sym);
	    parse(sym, S_format);
	    parse(sym, S_equal);
	    r->date_format = strdup(sym->buf);
	    tac_sym_get(sym);
	    continue;
	case S_log:
	    tac_sym_get(sym);
	    switch (sym->code) {
	    case S_separator:
		tac_sym_get(sym);
		parse(sym, S_equal);
		r->log_separator = strdup(sym->buf);
		r->log_separator_len = strlen(sym->buf);
		tac_sym_get(sym);
		break;
	    case S_equal:
		parse_log(sym, r);
		break;
	    default:
		parse_error_expect(sym, S_limit, S_timeout, S_unknown);
	    }
	    continue;
	case S_userid:		// deprecate?
	    top_only(sym, r);
	    parse_userid(sym, &config.userid, &config.groupid);
	    continue;
	case S_groupid:	// deprecate?
	    top_only(sym, r);
	    parse_groupid(sym, &config.groupid);
	    continue;
	case S_umask:
	    top_only(sym, r);
	    parse_umask(sym, &config.mask);
	    continue;
	case S_retire:
	    top_only(sym, r);
	    tac_sym_get(sym);
	    switch (sym->code) {
	    case S_limit:
		tac_sym_get(sym);
		parse(sym, S_equal);
		config.retire = parse_int(sym);
		continue;
	    case S_timeout:
		tac_sym_get(sym);
		parse(sym, S_equal);
		config.suicide = parse_seconds(sym) + io_now.tv_sec;
		continue;
	    default:
		parse_error_expect(sym, S_limit, S_timeout, S_unknown);
	    }
	case S_type7key:
	    top_only(sym, r);
	    tac_sym_get(sym);
	    parse(sym, S_equal);
	    config.c7xlat = strdup(sym->buf);
	    config.c7xlat_len = strlen(sym->buf);
	    tac_sym_get(sym);
	    continue;
	case S_separation:
	    tac_sym_get(sym);
	    parse(sym, S_tag);
	    parse(sym, S_equal);
	    r->separator = sym->buf[0];
	    tac_sym_get(sym);
	    continue;
	case S_user:
	case S_group:
	    parse_user(sym, r);
	    continue;
	case S_acl:
	    top_only(sym, r);
	    parse_tac_acl(sym);
	    continue;
	case S_mavis:
	    tac_sym_get(sym);
	    switch (sym->code) {
	    case S_module:
		if (r->mcx_inherited == BISTATE_YES)
		    r->mcx = NULL, r->mcx_inherited = BISTATE_NO;
		if (parse_mavismodule(&r->mcx, common_data.io, sym))
		    scm_fatal();
		continue;
	    case S_path:
		parse_mavispath(sym);
		continue;
	    case S_cache:
		tac_sym_get(sym);
		parse(sym, S_timeout);
		parse(sym, S_equal);
		r->caching_period = parse_seconds(sym);
		continue;
	    case S_noauthcache:
		tac_sym_get(sym);
		r->mavis_noauthcache = BISTATE_YES;
		continue;
	    case S_user:
		tac_sym_get(sym);
		parse(sym, S_filter);
		parse(sym, S_equal);
		if (sym->code == S_not) {
		    r->mavis_user_acl_negate = BISTATE_YES;
		    tac_sym_get(sym);
		}
		r->mavis_user_acl = tac_acl_lookup(sym->buf);
		if (!r->mavis_user_acl)
		    parse_error(sym, "ACL '%s' not found)", sym->buf);
		tac_sym_get(sym);
		continue;
	    default:
		parse_error_expect(sym, S_module, S_path, S_cache, S_unknown);
	    }
	case S_enable:
	    tac_sym_get(sym);
	    parse(sym, S_user);
	    parse(sym, S_acl);
	    parse(sym, S_equal);
	    r->enable_user_acl = tac_acl_lookup(sym->buf);
	    if (!r->enable_user_acl)
		parse_error(sym, "ACL '%s' not found)", sym->buf);
	    tac_sym_get(sym);
	    continue;
	case S_host:
	    parse_host(sym, r);
	    continue;
	case S_timespec:
	    top_only(sym, r);
	    parse_timespec(timespectable, sym);
	    continue;
	case S_anonenable:
	    tac_sym_get(sym);
	    parse(sym, S_equal);
	    r->anon_enable = parse_tristate(sym);
	    continue;
	case S_augmented_enable:
	    tac_sym_get(sym);
	    parse(sym, S_equal);
	    r->augmented_enable = parse_tristate(sym);
	    continue;
	case S_time:
	    top_only(sym, r);
	    tac_sym_get(sym);
	    parse(sym, S_zone);
	    parse(sym, S_equal);
	    setenv("TZ", sym->buf, 1);
	    tzset();
	    tac_sym_get(sym);
	    continue;
	case S_realm:
	    {
		tac_realm *new_realm;
		top_only(sym, r);
		tac_sym_get(sym);
		parse(sym, S_equal);
		new_realm = get_realm(sym->buf);
		tac_sym_get(sym);
		parse(sym, S_openbra);
		parse_decls_real(sym, new_realm);
		parse(sym, S_closebra);
		continue;
	    }
	case S_trace:
	case S_debug:
	    sym_get(sym);
	    switch (sym->code) {
	    case S_redirect:
		sym_get(sym);
		parse(sym, S_equal);
		if (freopen(sym->buf, "w+", stderr)) {
		    common_data.debug_redirected = 1;
		    common_data.font_blue = "";
		    common_data.font_red = "";
		    common_data.font_plain = "";
		    common_data.font_bold = "";
		}
		sym_get(sym);
		break;
	    case S_equal:
		parse(sym, S_equal);
		parse_debug(sym, &r->debug);
		break;
	    default:
		parse_error_expect(sym, S_redirect, S_equal, S_unknown);
	    }
	    continue;
	case S_rewrite:
	    sym_get(sym);
	    parse_rewrite(sym, r);
	    continue;
	case S_accept:
	    top_only(sym, r);
	    tac_sym_get(sym);
	    parse(sym, S_haproxy);
	    parse(sym, S_equal);
	    config.haproxy = parse_bool(sym) ? 1 : 0;
	    continue;
	case S_syslog:
	case S_proctitle:
	case S_coredump:
	case S_alias:
	case S_cleanup:
	    top_only(sym, r);
	    parse_common(sym);
	    continue;
	default:
	    parse_error(sym, "Unrecognized token '%s'", sym->buf);
	}
}

void parse_decls(struct sym *sym)
{
    parse_decls_real(sym, config.top_realm);
}


static time_t parse_date(struct sym *sym, time_t offset)
{
    int m, d, y;
    long long ll;

    if (3 == sscanf(sym->buf, "%d-%d-%d", &y, &m, &d)) {
	struct tm tm;
	memset(&tm, 0, sizeof(tm));

	tm.tm_year = y - 1900;
	tm.tm_mon = m - 1;
	tm.tm_mday = d;
	tac_sym_get(sym);
	return mktime(&tm) + offset;
    }
    if (1 == sscanf(sym->buf, "%lld", &ll)) {
	tac_sym_get(sym);
	return (time_t) ll;
    }
    parse_error(sym, "Unrecognized date '%s' (expected format: YYYY-MM-DD)", sym->buf);

    return (time_t) 0;
}

void free_user(tac_user * user)
{
    struct tac_acllist **aclgrp = &user->nas_member_acl;
    while (*aclgrp) {
	radix_drop(&(*aclgrp)->u.rt, NULL);
	aclgrp = &(*aclgrp)->next;
    }
    radix_drop(&user->nac_range, NULL);
    RB_tree_delete(user->svcs);
    RB_tree_delete(user->svc_prohibit);
#ifdef WITH_PCRE2
    mempool_destroy(user->pool_pcre);
#endif
    mempool_destroy(user->pool_regex);
    mempool_destroy(user->pool);
}

struct groups_s;
static int cmp_groups(struct groups_s *, struct groups_s *);
static struct pwdat *passwd_deny = NULL;
static struct pwdat *passwd_mavis = NULL;
static struct pwdat *passwd_login = NULL;
static struct pwdat *passwd_deny_dflt = NULL;
static struct pwdat *passwd_mavis_dflt = NULL;
static struct pwdat *passwd_login_dflt = NULL;
static struct pwdat *passwd_permit = NULL;

tac_user *new_user(char *name, enum token type, tac_realm * r)
{
    rb_tree_t *pool = NULL;
    tac_user *user;

    report(NULL, LOG_DEBUG, DEBUG_CONFIG_FLAG, "creating user %s in realm %s", name, r->name);

    if (type == S_user)
	pool = mempool_create();
    user = mempool_malloc(pool, sizeof(tac_user) + strlen(name));
    strcpy(user->name, name);
    user->svc_dflt = S_unknown;
    user->pool = pool;
    user->realm = r;
    if (type == S_user) {
#ifdef WITH_PCRE2
	user->pool_pcre = tac_pcrepool_create();
#endif
	user->pool_regex = tac_regpool_create();
    }
    user->svcs = RB_tree_new(compare_svc, (void (*)(void *)) free_svc);
    user->chalresp = TRISTATE_DUNNO;
    user->hushlogin = TRISTATE_DUNNO;

    return user;
}

int parse_user_profile(struct sym *sym, tac_user * user)
{
    sym->env_valid = 1;
    if (setjmp(sym->env))
	return -1;
    sym_init(sym);
    parse_user_attr(sym, user, S_user);
    parse_user_final(user);
    return 0;
}

int parse_user_profile_fmt(struct sym *sym, tac_user * user, char *fmt, ...)
{
    va_list ap;
    int l, len = 2 * MAX_INPUT_LINE_LEN;
    char *s = alloca(len);

    va_start(ap, fmt);
    l = vsnprintf(s, len, fmt, ap) + 1;
    if (l > len) {
	s = alloca(l);
	vsnprintf(s, l, fmt, ap);
    }
    va_end(ap);
    sym->in = sym->tin = s;
    sym->len = sym->tlen = l;
    return parse_user_profile(sym, user);
}

static void parse_user(struct sym *sym, tac_realm * r)
{
    tac_user *n, *user;
    enum token user_or_group = sym->code;
    rb_tree_t *rbt = NULL;
    enum token type = sym->code;

    tac_sym_get(sym);

    if (user_or_group == S_user && sym->code == S_backend) {
	parse(sym, S_backend);
	parse(sym, S_equal);
	switch (sym->code) {
	case S_mavis:
	    r->mavis_userdb = BISTATE_YES;
	    break;
	case S_local:
	    r->mavis_userdb = BISTATE_NO;
	    break;
	default:
	    parse_error_expect(sym, S_mavis, S_local, S_unknown);
	}
	tac_sym_get(sym);
	return;
    }

    if (user_or_group == S_group && sym->code == S_realm) {
	tac_sym_get(sym);
	parse(sym, S_equal);
	r->group_realm = get_realm(sym->buf);
	tac_sym_get(sym);
	return;
    }

    if (user_or_group == S_group && r->group_realm == config.top_realm)
	r->group_realm = r;

    if (r == config.top_realm) {
	if (sym->code == S_realm) {
	    tac_sym_get(sym);
	    r = get_realm(sym->buf);
	    tac_sym_get(sym);
	}
    }

    rbt = (user_or_group == S_user) ? r->usertable : r->grouptable;

    parse(sym, S_equal);
    user = new_user(sym->buf, type, r);
    user->line = sym->line;

    n = (tac_user *) RB_lookup(rbt, (void *) user);
    if (n)
	parse_error(sym, "%s '%s' already defined at line %u", type == S_user ? "User" : "Group", user->name, n->line);

    tac_sym_get(sym);
    parse_user_attr(sym, user, user_or_group);
    parse_user_final(user);
    RB_insert(rbt, user);
}

#define C radix_add_members_data
static struct {
    radixtree_t *rt;
    struct groups_s *g;
} C;

static void radix_add_members_func(struct in6_addr *addr, int mask, void *payload __attribute__((unused)), void *data __attribute__((unused)))
{
    radix_add(C.rt, addr, mask, C.g);
}

static void radix_add_members(struct sym *sym, radixtree_t * rt, char *s, struct groups_s *g, tac_realm * r)
{
    tac_host h, *hp;

    h.name = s;
    hp = RB_lookup(hosttable, (void *) &h);
    if (hp) {
	C.rt = rt;
	C.g = g;
	radix_walk(hp->addrtree, radix_add_members_func, NULL);
    } else
	switch (radix_add_str(rt, s, g)) {
	case -1:
	    parse_error(sym, "Expected a group name or an IP address or " "network in CIDR notation, but got '%s'.", s);
	case +1:
	    if (r->skip_conflicting_groups)
		report(NULL, LOG_ERR, ~0, "%s:%u: Group membership for network %s is already defined", sym->filename, sym->line, s);
	    else
		parse_error(sym, "Group membership for network %s is already defined.", s);
	default:;
	}
}

#undef C

static char hexbyte(char *s)
{
    char *h = "\0\01\02\03\04\05\06\07\010\011\0\0\0\0\0\0" "\0\012\013\014\015\016\017\0\0\0\0\0\0\0\0\0";
    return (h[(s[0] - '0') & 0x1F] << 4) | h[(s[1] - '0') & 0x1F];
}

static int c7decode(char *in)
{
    int seed;
    char *out = in;
    size_t len = strlen(in);

    if (len & 1 || len < 4)
	return -1;

    len -= 2;
    seed = 10 * (in[0] - '0') + in[1] - '0';
    in += 2;

    while (len) {
	*out = hexbyte(in) ^ config.c7xlat[seed % config.c7xlat_len];
	in += 2, seed++, len -= 2, out++;
    }

    *out = 0;

    return 0;
}

static struct pwdat *parse_pw(struct sym *, rb_tree_t *, int);
static void parse_acl_cond(struct sym *, tac_user *, struct tac_acl **, int *);

static struct upwdat *new_upwdat(struct rb_tree *pool, tac_realm * r)
{
    struct upwdat *pp = mempool_malloc(pool, sizeof(struct upwdat));
    int i;
    for (i = 0; i <= PW_MAVIS; i++)
	pp->passwd[i] = passwd_deny_dflt;
    if (r->mavis_login)
	pp->passwd[PW_LOGIN] = passwd_mavis_dflt;
    if (r->mavis_pap)
	pp->passwd[PW_PAP] = passwd_mavis_dflt;
    if (r->pap_login) {
	if (r->mavis_login)
	    pp->passwd[PW_PAP] = passwd_mavis_dflt;
	else
	    pp->passwd[PW_PAP] = passwd_login_dflt;
    }
    return pp;
}

static void parse_error_order(struct sym *sym, char *what)
{
    report(NULL, LOG_ERR, ~0, "%s:%u: Statement may have no effect. %s directives need to be ordered by "
	   "acl name, with definitions without acl coming last.", sym->filename, sym->line, what);
}


static void parse_pw_acl(struct sym *sym, tac_user * user, enum pw_ix pw_ix, int cry)
{
    struct tac_acl *a = NULL;
    int negate = 0;
    struct tac_acllist **pa = &user->passwd_acllist;
    struct pwdat **pp;

    parse_acl_cond(sym, user, &a, &negate);
    while (*pa && ((*pa)->acl != a || (*pa)->negate != negate)) {
	if (a && !(*pa)->acl)
	    parse_error_order(sym, "password");
	pa = &(*pa)->next;
    }
    if (!(*pa)) {
	*pa = mempool_malloc(user->pool, sizeof(struct tac_acllist));
	(*pa)->u.passwdp = new_upwdat(user->pool, user->realm);
	(*pa)->acl = a;
	(*pa)->negate = negate;
    }
    if ((*pa)->next)
	parse_error_order(sym, "password");
    else {
	pp = (*pa)->u.passwdp->passwd;
	pp[pw_ix] = parse_pw(sym, user->pool, cry);
    }
}

static struct pwdat *parse_pw(struct sym *sym, rb_tree_t * pool, int cry)
{
    struct pwdat *pp = NULL;
    enum token sc;
    int c7 = 0;
    parse(sym, S_equal);

    switch (sym->code) {
    case S_mavis:
	tac_sym_get(sym);
	return passwd_mavis;
    case S_permit:
	tac_sym_get(sym);
	return passwd_permit;
    case S_login:
	tac_sym_get(sym);
	return passwd_login;
    case S_deny:
	tac_sym_get(sym);
	return passwd_deny;
    case S_crypt:
	if (cry)
	    break;
    case S_clear:
    case S_follow:
	break;
    case S_7:
	sym->code = S_clear;
	c7++;
	break;
    default:
	parse_error_expect(sym, S_clear, S_permit, S_deny, S_follow, S_login, cry ? S_crypt : S_unknown, S_unknown);
    }

    sc = sym->code;
    tac_sym_get(sym);

    if (c7 && c7decode(sym->buf))
	parse_error(sym, "type 7 password is malformed");

    pp = mempool_malloc(pool, sizeof(struct pwdat) + strlen(sym->buf));
    pp->type = sc;
    strcpy(pp->value, sym->buf);
    if (sc == S_follow) {
	char *t = pp->value;
	while (*t) {
	    if (*t == ' ')
		*t = '\n';
	    t++;
	}
    }
    tac_sym_get(sym);
    return pp;
}

static void parse_acl_cond(struct sym *sym, tac_user * user, struct tac_acl **a, int *negate)
{
    if (sym->code == S_acl) {
	tac_sym_get(sym);
	if (sym->code == S_not) {
	    *negate = 1;
	    tac_sym_get(sym);
	}
	*a = tac_acl_lookup(sym->buf);
	if (!*a)
	    parse_error(sym, "ACL '%s' not found (user/group: %s)", sym->buf, user->name);
	tac_sym_get(sym);
    }
}

static struct pwdat **lookup_pwdat_by_acl(struct sym *sym, tac_user * user, struct tac_acl *a, int negate)
{
    struct tac_acllist **pa = &user->passwd_acllist;
    while (*pa && ((*pa)->acl != a || (*pa)->negate != negate)) {
	if (a && !(*pa)->acl)
	    parse_error_order(sym, "password");
	pa = &(*pa)->next;
    }
    if (!(*pa)) {
	*pa = mempool_malloc(user->pool, sizeof(struct tac_acllist));
	(*pa)->u.passwdp = new_upwdat(user->pool, user->realm);
	(*pa)->acl = a;
	(*pa)->negate = negate;
    }
    if ((*pa)->next)
	parse_error_order(sym, "password");

    return (*pa)->u.passwdp->passwd;


}

static void parse_password(struct sym *sym, tac_user * user)
{
    struct tac_acl *a = NULL;
    int negate = 0;
    struct pwdat **pp;
    enum pw_ix pw_ix = 0;
    int i;

    tac_sym_get(sym);

    parse_acl_cond(sym, user, &a, &negate);

    if (sym->code == S_openbra) {
	tac_sym_get(sym);

	pp = lookup_pwdat_by_acl(sym, user, a, negate);

	while (1) {
	    int cry = 0;
	    switch (sym->code) {
	    case S_closebra:
		tac_sym_get(sym);
		return;
	    case S_login:
		pw_ix = PW_LOGIN, cry = 1;
		break;
	    case S_pap:
		pw_ix = PW_PAP, cry = 1;
		break;
#ifdef SUPPORT_ARAP
	    case S_arap:
		pw_ix = PW_ARAP;
		break;
#endif
	    case S_chap:
		pw_ix = PW_CHAP;
		break;
	    case S_mschap:
		pw_ix = PW_MSCHAP;
		break;
#ifdef SUPPORT_SENDAUTH
	    case S_opap:
		pw_ix = PW_OPAP;
		break;
#endif
	    default:
		parse_error_expect(sym, S_login, S_pap,
#ifdef SUPPORT_ARAP
				   S_arap,
#endif
				   S_chap, S_mschap,
#ifdef SUPPORT_SENDAUTH
				   S_opap,
#endif
				   S_unknown);
	    }
	    tac_sym_get(sym);
	    pp[pw_ix] = parse_pw(sym, user->pool, cry);
	}
	return;
    }

    switch (sym->code) {
    case S_login:
    case S_pap:
    case S_arap:
    case S_chap:
    case S_mschap:
    case S_opap:
	return;

    case S_acl:
	if (!a)
	    parse_acl_cond(sym, user, &a, &negate);
    default:;
    }

    pp = lookup_pwdat_by_acl(sym, user, a, negate);

    for (pw_ix = 0; pw_ix < PW_MAVIS && ((pp[pw_ix] != passwd_deny_dflt) && (pp[pw_ix] != passwd_login_dflt) && (pp[pw_ix] != passwd_mavis_dflt)); pw_ix++);

    parse_pw_acl(sym, user, pw_ix, 0);

    if (pw_ix < PW_MAVIS)
	for (i = 0; i < PW_MAVIS; i++)
	    if (
#ifdef SUPPORT_SENDAUTH
		   i != PW_OPAP &&
#endif
		   ((pp[i] == passwd_deny_dflt) || (pp[i] == passwd_login_dflt) || (pp[i] == passwd_mavis_dflt)))
		pp[i] = pp[pw_ix];
}

struct groups_s {
    tac_user **g;
    int i;
};

static int cmp_groups(struct groups_s *a, struct groups_s *b)
{
    int i;
    if (a->i != b->i)
	return 1;
    for (i = 0; i < a->i; i++)
	if (a->g[i] != b->g[i])
	    return 1;
    return 0;
}

static void add_member(struct sym *sym, radixtree_t * rt, tac_user * user, char *grp, char *range, tac_realm * r)
{
    int i = 2;
    char *p;
    struct groups_s *ams = mempool_malloc(user->pool, sizeof(struct groups_s));

    p = grp;
    for (; *p == '/'; p++);
    while ((p = strchr(p, '/'))) {
	for (; *p == '/'; p++);
	if (*p)
	    i++;
    }

    ams->g = mempool_malloc(user->pool, i * sizeof(tac_user *));

    p = grp;
    for (; *p == '/'; p++);
    while (p && *p) {
	char *sl = strchr(p, '/');
	if (sl) {
	    *sl++ = 0;
	    for (; *sl == '/'; sl++);
	}
	ams->g[ams->i] = lookup_user(user->realm->group_realm->grouptable, p);
	if (ams->g[ams->i])
	    ams->i++;
	else {
	    if (r->skip_missing_groups)
		report(NULL, LOG_ERR, ~0, "%s:%u: Group '%s' not found", sym->filename, sym->line, p);
	    else
		parse_error(sym, "Group '%s' not found%s", p, user->dynamic ? " (consider adding 'skip missing groups = yes' to your configuration)" : "");
	}
	p = sl;
    }
    if (ams->i)
	radix_add_members(sym, rt, range, ams, r);
    else {
	mempool_free(user->pool, ams->g);
	mempool_free(user->pool, ams);
    }
}

static struct tac_acl *tac_acl_lookup(char *s)
{
    struct tac_acl *a;
    size_t l = strlen(s);
    l = strlen(s);
    a = alloca(sizeof(struct tac_acl) + l);
    strcpy(a->name, s);
    return (struct tac_acl *) RB_lookup(acltable, a);
}

static void parse_member(struct sym *sym, tac_user * user, tac_realm * r)
{
    struct tac_acl *acfg = NULL, *a = NULL;
    int negate = 0;
    struct tac_acllist **aclgrp = &user->nas_member_acl;
    tac_sym_get(sym);

    parse_acl_cond(sym, user, &acfg, &negate);

    if (acfg) {
	while (*aclgrp && ((*aclgrp)->acl != acfg || (*aclgrp)->negate != negate)) {
	    if (!(*aclgrp)->acl)
		parse_error_order(sym, "member");
	    aclgrp = &(*aclgrp)->next;
	}
	if (!(*aclgrp)) {
	    *aclgrp = mempool_malloc(user->pool, sizeof(struct tac_acllist));
	    (*aclgrp)->u.rt = radix_new(NULL, (int (*)(void *, void *)) cmp_groups);
	    (*aclgrp)->acl = acfg;
	    (*aclgrp)->negate = negate;
	} else if ((*aclgrp)->next) {
	    parse_error_order(sym, "member");
	}
    }

    parse(sym, S_equal);

    do {
	tac_user *g = NULL;
	char *range = strchr(sym->buf, '@');
	struct stringlist *hl = NULL;

	if (sym->code == S_eof)
	    parse_error(sym, "EOF unexpected");

	if (range) {
	    int rlen;
	    *range++ = 0;
	    rlen = strlen(range);
	    hl = mempool_malloc(user->pool, sizeof(struct stringlist) + rlen);
	    strncpy(hl->s, range, rlen);
	} else if (!strchr(sym->buf, '/') && (g = lookup_user(user->realm->group_realm->grouptable, sym->buf)))
	    hl = g->nas_limit_dflt;

	if (!hl) {
	    int rlen;
	    range = inet_any();
	    rlen = strlen(range);
	    hl = mempool_malloc(user->pool, sizeof(struct stringlist) + rlen);
	    memcpy(hl->s, range, rlen);
	}

	while (hl) {
	    tac_realm *tr = r;
	    radixtree_t *t;
	    tac_host h, *hp;
	    h.name = hl->s;
	    hp = RB_lookup(hosttable, (void *) &h);
	    if (hp) {
		a = tac_acl_lookup(sym->buf);
		// tr = hp->realm; // FIXME Use hp->aaa_realm or just drop this line?
	    }
	    if (acfg) {
		a = acfg;
	    } else {
		char an[512];
		aclgrp = &user->nas_member_acl;
		snprintf(an, sizeof(an), "__internal__realm_%s", tr->name);
		a = tac_acl_lookup(an);
		if (!a) {
		    char acl[1024];
		    struct sym sym;
		    snprintf(acl, sizeof(acl), "acl = %s { realm = %s }", an, tr->name);
		    memset(&sym, 0, sizeof(sym));
		    sym.filename = "__internal__";
		    sym.line = 1;
		    sym.in = sym.tin = acl;
		    sym.len = sym.tlen = strlen(acl);
		    sym_init(&sym);
		    parse_tac_acl(&sym);
		    a = tac_acl_lookup(an);
		}
		while (*aclgrp && ((*aclgrp)->acl != a || (*aclgrp)->negate != negate)) {
		    if (!(*aclgrp)->acl)
			parse_error_order(sym, "member");
		    aclgrp = &(*aclgrp)->next;
		}
		if (!(*aclgrp)) {
		    *aclgrp = mempool_malloc(user->pool, sizeof(struct tac_acllist));
		    (*aclgrp)->u.rt = radix_new(NULL, (int (*)(void *, void *)) cmp_groups);
		    (*aclgrp)->acl = a;
		    (*aclgrp)->negate = negate;
		} else if ((*aclgrp)->next) {
		    parse_error_order(sym, "member");
		}
	    }
	    t = (*aclgrp)->u.rt;

	    add_member(sym, t, user, sym->buf, hl->s, r);
	    hl = hl->next;
	}

	tac_sym_get(sym);
    }
    while (parse_comma(sym));
}

static void parse_enable(struct sym *sym, rb_tree_t * pool, struct pwdat **enable, char *enable_implied)
{
    int level = TAC_PLUS_PRIV_LVL_MAX, i;

    tac_sym_get(sym);
    if (1 == sscanf(sym->buf, "%d", &level)) {
	if (level < TAC_PLUS_PRIV_LVL_MIN)
	    level = TAC_PLUS_PRIV_LVL_MIN;
	else if (level > TAC_PLUS_PRIV_LVL_MAX)
	    level = TAC_PLUS_PRIV_LVL_MAX;
	tac_sym_get(sym);
    }

    enable[level] = parse_pw(sym, pool, 1);
    enable_implied[level] = 0;
    for (i = level - 1; i >= TAC_PLUS_PRIV_LVL_MIN; i--) {
	if (enable_implied[i] > level || !enable[i]) {
	    enable_implied[i] = level;
	    enable[i] = enable[level];
	}
    }
}

static enum tac_acl_type parse_aclregex(struct sym *, struct acl_element *);
static enum tac_acl_type parse_regex(struct sym *, tac_user *, void **);

static void parse_host_acl(struct sym *sym, struct tac_acllist **tal)
{
    while (*tal)
	tal = &(*tal)->next;
    *tal = calloc(1, sizeof(struct tac_acllist));
    (*tal)->u.token = S_permit;
    tac_sym_get(sym);
    parse(sym, S_equal);
    switch (sym->code) {
    case S_deny:
	(*tal)->u.token = S_deny;
    case S_permit:
	tac_sym_get(sym);
    default:;
    }
    if (sym->code == S_not) {
	(*tal)->negate = 1;
	tac_sym_get(sym);
    }
    (*tal)->acl = tac_acl_lookup(sym->buf);
    if (!(*tal)->acl)
	parse_error(sym, "ACL '%s' not found (line: %d)", sym->buf, sym->line);
    tac_sym_get(sym);
}

static struct tac_acllist *eval_tac_acllist(tac_session *, char *, struct tac_acllist **);

enum token is_valid_nac_host(tac_session * session)
{
    if (!session->nac_address_valid)
	return S_permit;

    tac_host *arr[129];
    int arr_min = 0, arr_max = 0, i;

    memset(arr, 0, sizeof(arr));

    if (radix_lookup(session->ctx->nac_realm->hosttree, &session->nac_address, (void *) arr)) {
	for (arr_max = 0; arr_max < 129 && arr[arr_max]; arr_max++);
	arr_max--;

	for (i = arr_max; i > -1 && !arr[i]->orphan; i--);
	arr_min = i;
	for (i = arr_max; i > arr_min; i--)
	    if (arr[i]->valid_for_nac != TRISTATE_DUNNO)
		return (arr[i]->valid_for_nac == TRISTATE_YES) ? S_permit : S_deny;
    }
    return S_permit;
}


enum token eval_host_acl(tac_session * session)
{
    tac_host **h = NULL;
    struct tac_acllist *a = NULL;
    enum token res = is_valid_nac_host(session);

    if (res == S_deny)
	return res;

    for (h = session->ctx->hostchain; !a && *h; h++) {
	if ((*h)->access_acl) {
	    res = S_deny;
	    a = eval_tac_acllist(session, NULL, &(*h)->access_acl);
	    if (a) {
		switch (a->u.token) {
		case S_deny:
		case S_permit:
		    return a->u.token;
		default:
		    a = NULL;
		}
	    }
	}
    }
    return res;
}

struct upwdat *eval_passwd_acl(tac_session * session)
{
    if (session->user) {
	struct tac_acllist *a = eval_tac_acllist(session, NULL, &session->user->passwd_acllist);
	if (a)
	    return a->u.passwdp;

	session->user->passwd_acllist = mempool_malloc(session->user->pool, sizeof(struct tac_acllist));
	session->user->passwd_acllist->u.passwdp = new_upwdat(session->user->pool, session->user->realm);
	return session->user->passwd_acllist->u.passwdp;
    }
    // shouldn't happen
    return new_upwdat(session->pool, session->ctx->aaa_realm);
}

static void parse_user_acl(struct sym *sym, tac_user * user, struct tac_acllist **tal)
{
    while (*tal)
	tal = &(*tal)->next;
    *tal = mempool_malloc(user->pool, sizeof(struct tac_acllist));
    (*tal)->u.token = S_permit;
    tac_sym_get(sym);
    parse(sym, S_equal);
    switch (sym->code) {
    case S_deny:
	(*tal)->u.token = S_deny;
    case S_permit:
	tac_sym_get(sym);
    default:;
    }
    if (sym->code == S_not) {
	(*tal)->negate = 1;
	tac_sym_get(sym);
    }
    (*tal)->acl = tac_acl_lookup(sym->buf);
    if (!(*tal)->acl)
	parse_error(sym, "ACL '%s' not found (user/group: %s)", sym->buf, user->name);
    tac_sym_get(sym);
}

static void radix_copy_func(struct in6_addr *addr, int mask, void *payload, void *data)
{
    radix_add((radixtree_t *) data, addr, mask, payload);
}


static void append_aclelement(struct acl_element **to, struct acl_element *from)
{
    if (!from)
	return;
    while (*to)
	to = &(*to)->next;
    while (from) {
	*to = calloc(1, sizeof(struct acl_element));
	memcpy(*to, from, sizeof(struct acl_element));
	to = &(*to)->next;
	from = from->next;
    }
}

static void append_acllist(struct tac_acllist **to, struct tac_acllist *from)
{
    if (!from)
	return;
    while (*to)
	to = &(*to)->next;
    while (from) {
	*to = calloc(1, sizeof(struct tac_acllist));
	memcpy(*to, from, sizeof(struct tac_acllist));
	to = &(*to)->next;
	from = from->next;
    }
}

static void rb_merge(rb_tree_t ** to, rb_tree_t * from, int (*compare)(const void *, const void *))
{
    rb_node_t *r;

    if (RB_empty(from))
	return;
    if (!*to)
	*to = RB_tree_new(compare, NULL);

    r = RB_first(from);
    while (r) {
	RB_insert(*to, RB_payload_get(r));
	r = RB_next(r);
    }
}

static void merge_svcs(tac_user * user, rb_tree_t ** to, rb_tree_t * from)
{
    rb_node_t *r;

    if (RB_empty(from))
	return;
    if (!*to)
	*to = RB_tree_new(compare_svc, NULL);

    r = RB_first(from);
    while (r) {
	struct node_svc *sf = RB_payload(r, struct node_svc *);
	struct node_svc *st = alloca(sizeof(struct node_svc) + strlen(sf->name));
	struct node_svc **sn;
	st->type = sf->type;
	strcpy(st->name, sf->name);
	st = RB_lookup(*to, st);
	sn = &st;
	while (st && (st->acl != sf->acl || st->negate != sf->negate))
	    st = st->next;

	if (!st) {
	    st = calloc(1, sizeof(struct node_svc) + strlen(sf->name));
	    strcpy(st->name, sf->name);
	    st->type = sf->type;
	    st->acl = sf->acl;
	    st->negate = sf->negate;
	    if (*sn) {
		while (*sn)
		    sn = &(*sn)->next;
		*sn = st;
	    } else
		RB_insert(user->svcs, st);
	}

	if (sf->attrs_m) {
	    int i = st->cnt_m;
	    st->cnt_m += sf->cnt_m;
	    st->attrs_m = realloc(st->attrs_m, sizeof(char *) * (st->cnt_m + 1));
	    memcpy(st->attrs_m + i, sf->attrs_m, sf->cnt_m * sizeof(char *));
	    st->attrs_m[st->cnt_m] = NULL;
	}
	if (sf->attrs_a) {
	    int i = st->cnt_a;
	    st->cnt_a += sf->cnt_a;
	    st->attrs_a = realloc(st->attrs_a, sizeof(char *) * (st->cnt_a + 1));
	    memcpy(st->attrs_a + i, sf->attrs_a, sf->cnt_a * sizeof(char *));
	    st->attrs_a[st->cnt_a] = NULL;
	}
	if (sf->attrs_o) {
	    int i = st->cnt_o;
	    st->cnt_o += sf->cnt_o;
	    st->attrs_o = realloc(st->attrs_o, sizeof(char *) * (st->cnt_o + 1));
	    memcpy(st->attrs_o + i, sf->attrs_o, sf->cnt_o * sizeof(char *));
	    st->attrs_o[st->cnt_o] = NULL;
	}

	append_acllist(&st->acllist, sf->acllist);

	if (st->sub_dflt == S_unknown)
	    st->sub_dflt = sf->sub_dflt;
	if (st->attr_dflt == S_unknown)
	    st->attr_dflt = sf->attr_dflt;
	if (!RB_empty(sf->sub)) {
	    rb_node_t *s;
	    switch (sf->type) {
	    case S_shell:
		if (st->sub == NULL)
		    st->sub = RB_tree_new(compare_cmd, NULL);
		for (s = RB_first(sf->sub); s; s = RB_next(s)) {
		    struct node_cmd *cf = RB_payload(s, struct node_cmd *);
		    struct node_cmd *ct = RB_lookup(st->sub, cf);
		    if (!ct) {
			size_t namelen = strlen(cf->name);
			ct = calloc(1, sizeof(struct node_cmd) + namelen);
			memcpy(ct->name, cf->name, namelen);
			RB_insert(st->sub, ct);
		    }
		    if (cf->perm) {
			struct node_perm **pt = &ct->perm;
			struct node_perm *pf = cf->perm;
			while (*pt)
			    pt = &(*pt)->next;
			while (pf) {
			    size_t l = sizeof(struct node_perm) + strlen(pf->name);
			    *pt = calloc(1, l);
			    memcpy(*pt, pf, l);
			    pt = &(*pt)->next;
			    pf = pf->next;
			}
		    }

		    if (!ct->msg_deny)
			ct->msg_deny = cf->msg_deny;
		    if (!ct->msg_permit)
			ct->msg_permit = cf->msg_permit;
		    if (!ct->msg_debug)
			ct->msg_debug = cf->msg_debug;
		}
		break;
	    default:
		merge_svcs(user, &st->sub, sf->sub);
	    }
	}
	if (!st->msg_deny)
	    st->msg_deny = sf->msg_deny;
	if (!st->msg_permit)
	    st->msg_permit = sf->msg_permit;
	if (!st->msg_debug)
	    st->msg_debug = sf->msg_debug;

	r = RB_next(r);
    }
}

static int merge_group(tac_user * to, tac_user * from, char *from_name)
{
    int i;
    if (!from)
	from = lookup_user(to->realm->group_realm->grouptable, from_name);
    if (!from)
	return -1;
    if (!to->msg)
	to->msg = from->msg;
    if (!to->valid_from)
	to->valid_from = from->valid_from;
    if (!to->valid_until)
	to->valid_until = from->valid_until;
    for (i = 0; i < TAC_PLUS_PRIV_LVL_MAX + 1; i++)
	if (to->enable_implied[i] != i && from->enable_implied[i] == i) {
	    int j;
	    to->enable[i] = from->enable[i];
	    for (j = 0; j < i; j++)
		if (to->enable_implied[j] == to->enable_implied[i])
		    to->enable_implied[j] = i;
	    to->enable_implied[i] = i;

	}
    if (to->svc_dflt == S_unknown)
	to->svc_dflt = from->svc_dflt;
    if (from->nac_range) {
	if (!to->nac_range)
	    to->nac_range = radix_new(NULL, NULL);
	radix_walk(from->nac_range, radix_copy_func, to->nac_range);
    }
    if (from->nas_range) {
	if (!to->nas_range)
	    to->nas_range = radix_new(NULL, NULL);
	radix_walk(from->nas_range, radix_copy_func, to->nas_range);
    }
    append_aclelement(&to->nac_regex, from->nac_regex);
    append_acllist(&to->acllist, from->acllist);
    append_acllist(&to->nas_member_acl, from->nas_member_acl);
    append_acllist(&to->tag_acl, from->tag_acl);

#if 0				// FIXME? Just using append_aclelement isn't sufficient here.
    for (i = 0; i <= PW_MAVIS; i++)
	if (!to->passwd[i])
	    to->passwd[i] = from->passwd[i];
#endif

    rb_merge(&to->svc_prohibit, from->svc_prohibit, NULL);
    merge_svcs(to, &to->svcs, from->svcs);

    return 0;
}

void parse_user_final(tac_user * user)
{
    struct tac_acllist **pa = &user->passwd_acllist;
    while (*pa && (*pa)->acl)
	pa = &(*pa)->next;
    if (!*pa) {
	*pa = mempool_malloc(user->pool, sizeof(struct tac_acllist));
	(*pa)->u.passwdp = new_upwdat(user->pool, user->realm);
    }
}

static void parse_user_attr(struct sym *sym, tac_user * user, enum token user_or_group)
{
    tac_realm *r = user->realm;

    parse(sym, S_openbra);

    while (1)
	switch (sym->code) {
	case S_eof:
	    parse_error(sym, "EOF unexpected");
	case S_acl:
	    parse_user_acl(sym, user, &user->acllist);
	    continue;
	case S_default:
	    tac_sym_get(sym);
	    parse(sym, S_service);
	    parse(sym, S_equal);
	    user->svc_dflt = parse_permission(sym);
	    continue;
	case S_prohibit:
	    tac_sym_get(sym);
	    parse(sym, S_service);
	    parse(sym, S_equal);
	    if (!user->svc_prohibit)
		user->svc_prohibit = RB_tree_new((int (*)(const void *, const void *))
						 strcmp, NULL);
	    RB_insert(user->svc_prohibit, mempool_strdup(user->pool, sym->buf));
	    tac_sym_get(sym);
	    continue;
	case S_service:
	    parse_svcs(sym, user);
	    continue;
	case S_clone:
	case S_template:
	    if (user_or_group != S_group)
		parse_error(sym, "Token %s not permitted in user context.", sym->buf);
	    tac_sym_get(sym);
	    parse(sym, S_equal);
	    if (merge_group(user, NULL, sym->buf))
		parse_error(sym, "Group '%s' not found", sym->buf);
	    tac_sym_get(sym);
	    continue;
	case S_member:
	    parse_member(sym, user, r);
	    continue;
	case S_mavis:
	    tac_sym_get(sym);
	    parse(sym, S_realm);
	    parse(sym, S_equal);
	    if (!user->dynamic)
		user->mavis_realm = get_realm(sym->buf);
	    tac_sym_get(sym);
	    continue;
	case S_client:
	    {
		struct groups_s *g = (struct groups_s *) 0xdeadbeaf;
		tac_sym_get(sym);
		if (sym->code == S_regex) {
		    struct acl_element **r = &user->nac_regex;
		    void *dummy;
		    tac_sym_get(sym);
		    sym->flag_parse_pcre = 1;
		    parse(sym, S_equal);
		    while (*r)
			r = &(*r)->next;
		    *r = mempool_malloc(user->pool, sizeof(struct acl_element));
		    switch (sym->code) {
		    case S_not:
		    case S_deny:
			(*r)->negate = 1;
		    case S_permit:
			tac_sym_get(sym);
		    default:;
		    }
		    (*r)->line = sym->line;
		    (*r)->string = mempool_strdup(user->pool, sym->buf);
		    dummy = &(*r)->blob.r;
		    (*r)->type = parse_regex(sym, user, dummy);
		    sym->flag_parse_pcre = 0;
		    continue;
		}
		parse(sym, S_equal);
		if (!user->nac_range)
		    user->nac_range = radix_new(NULL, NULL);
		do {
		    if (sym->code == S_eof)
			parse_error(sym, "EOF unexpected");
		    switch (sym->code) {
		    case S_not:
		    case S_deny:
			g = NULL;
		    case S_permit:
			tac_sym_get(sym);
		    default:;
		    }
		    radix_add_members(sym, user->nac_range, sym->buf, g, r);
		    tac_sym_get(sym);
		}
		while (parse_comma(sym));
		continue;
	    }
	case S_server:
	    {
		struct groups_s *g = (struct groups_s *) 0xdeadbeaf;
		tac_sym_get(sym);
		parse(sym, S_equal);
		if (!user->nas_range)
		    user->nas_range = radix_new(NULL, NULL);
		do {
		    switch (sym->code) {
		    case S_deny:
			g = NULL;
		    case S_permit:
			tac_sym_get(sym);
		    default:;
		    }
		    radix_add_members(sym, user->nas_range, sym->buf, g, r);
		    tac_sym_get(sym);
		}
		while (parse_comma(sym));
		continue;
	    }
	case S_valid:
	    tac_sym_get(sym);
	    switch (sym->code) {
	    case S_until:
		tac_sym_get(sym);
		parse(sym, S_equal);
		user->valid_until = parse_date(sym, 86400);
		break;
	    case S_from:
		tac_sym_get(sym);
	    default:
		parse(sym, S_equal);
		user->valid_from = parse_date(sym, 0);
		break;
	    }
	    continue;
	case S_expires:
	    report(NULL, LOG_ERR, ~0, "%s:%u: \"expires\" keyword is deprecated, use " "\"valid until\" with one day less", sym->filename, sym->line);
	    tac_sym_get(sym);
	    parse(sym, S_equal);
	    user->valid_until = parse_date(sym, 0);
	    continue;
	case S_debug:
	    tac_sym_get(sym);
	    parse(sym, S_equal);
	    parse_debug(sym, &user->debug);
	    continue;
	case S_message:
	    tac_sym_get(sym);
	    parse(sym, S_equal);
	    user->msg = mempool_strdup(user->pool, sym->buf);
	    tac_sym_get(sym);
	    continue;
	case S_login:
	    tac_sym_get(sym);
	    parse_pw_acl(sym, user, PW_LOGIN, 1);
	    continue;
	case S_pap:
	    tac_sym_get(sym);
	    parse_pw_acl(sym, user, PW_PAP, 1);
	    continue;
#ifdef SUPPORT_ARAP
	case S_arap:
	    tac_sym_get(sym);
	    parse_pw_acl(sym, user, PW_ARAP, 0);
	    continue;
#endif
	case S_chap:
	    tac_sym_get(sym);
	    parse_pw_acl(sym, user, PW_CHAP, 0);
	    continue;
	case S_mschap:
	    tac_sym_get(sym);
	    parse_pw_acl(sym, user, PW_MSCHAP, 0);
	    continue;
#ifdef SUPPORT_SENDAUTH
	case S_opap:
	    tac_sym_get(sym);
	    parse_pw_acl(sym, user, PW_OPAP, 0);
	    continue;
#endif
	case S_password:
	    parse_password(sym, user);
	    continue;
	case S_enable:
	    parse_enable(sym, user->pool, user->enable, user->enable_implied);
	    continue;
	case S_tag:
	    parse_tag(sym, user);
	    continue;
	case S_fallback_only:
	    tac_sym_get(sym);
	    user->fallback_only = 1;
	    continue;
	case S_hushlogin:
	    tac_sym_get(sym);
	    parse(sym, S_equal);
	    user->hushlogin = parse_tristate(sym);
	    continue;
	case S_closebra:
	    tac_sym_get(sym);
	    return;
	case S_nas:
	    if (user_or_group == S_group) {
		struct in6_addr a;
		int cm;
		tac_host h;

		tac_sym_get(sym);
		parse(sym, S_default);
		parse(sym, S_restriction);
		parse(sym, S_equal);
		h.name = sym->buf;

		if (RB_lookup(hosttable, (void *) &h) || !v6_ptoh(&a, &cm, sym->buf)) {
		    struct stringlist *s = mempool_malloc(user->pool,
							  sizeof(struct stringlist)
							  + strlen(sym->buf));
		    strcpy(s->s, sym->buf);
		    s->next = user->nas_limit_dflt;
		    user->nas_limit_dflt = s;
		} else
		    parse_error(sym, "Expected a hostname or an IP " "address/network in CIDR notation, " "but got '%s'.", sym->buf);
		tac_sym_get(sym);
		continue;
	    }
	    // Fallthrough
	default:
	    parse_error(sym, "Unrecognized keyword '%s' (user/group: %s)", sym->buf, user->name);
	}
}

static void add_host(struct sym *sym, radixtree_t * ht, tac_host * host)
{
    struct in6_addr a;
    int cm;
    if (v6_ptoh(&a, &cm, sym->buf)) {
	struct dns_forward_mapping *d = dns_lookup_a(dns_tree_a, sym->buf);

	if (d) {
	    while (d) {
		if (ht && radix_add(ht, &d->a, cm, host))
		    parse_error(sym, "Host '%s' already defined", sym->buf);
		radix_add(host->addrtree, &d->a, cm, host);

		d = d->next;
	    }
	    return;
	}

	parse_error(sym, "Expected an IP address or network in CIDR " "notation, but got '%s'.", sym->buf);
    }

    if (ht && radix_add(ht, &a, cm, host))
	parse_error(sym, "Host '%s' already defined", sym->buf);

    radix_add(host->addrtree, &a, cm, host);
}

static struct {
    tac_host *host;
} parse_file_data;

static void parse_file(char *url, radixtree_t * ht)
{
    struct sym sym;
    char *buf;
    int bufsize;

    memset(&sym, 0, sizeof(sym));
    sym.filename = url;
    sym.line = 1;

    sym.env_valid = 1;
    if (setjmp(sym.env))
	tac_exit(EX_CONFIG);

    if (cfg_open_and_read(url, &buf, &bufsize)) {
	report_cfg_error(LOG_ERR, ~0, "Couldn't open %s: %s", url, strerror(errno));
	report_cfg_error(LOG_ERR, ~0, "Exiting.");
	exit(EX_NOINPUT);
    }

    sym.tlen = sym.len = bufsize;
    sym.tin = sym.in = buf;

    sym_init(&sym);

    while (sym.code != S_eof) {
	add_host(&sym, ht, parse_file_data.host);
	tac_sym_get(&sym);
    }

    cfg_close(url, buf, bufsize);
}

static void parse_rewrite(struct sym *sym, tac_realm * r)
{
    tac_rewrite_expr **e;
    tac_rewrite *rewrite = alloca(sizeof(tac_rewrite));
    parse(sym, S_equal);
    rewrite->name = sym->buf;
    rewrite = RB_lookup(r->rewrite, rewrite);
    if (!rewrite) {
	rewrite = (tac_rewrite *) calloc(1, sizeof(tac_rewrite));
	rewrite->name = strdup(sym->buf);
	RB_insert(r->rewrite, rewrite);
    }
    e = &rewrite->expr;
    while (*e)
	e = &(*e)->next;
    tac_sym_get(sym);
    parse(sym, S_openbra);
    while (sym->code == S_rewrite) {
#ifdef WITH_PCRE2
	int errcode = 0;
	*e = (tac_rewrite_expr *) calloc(1, sizeof(tac_rewrite_expr));
	sym->flag_parse_pcre = 1;
	tac_sym_get(sym);
	if (sym->code == S_slash) {
	    PCRE2_SIZE erroffset;
	    (*e)->code =
		pcre2_compile((PCRE2_SPTR8) sym->buf, PCRE2_ZERO_TERMINATED, PCRE2_MULTILINE | common_data.regex_pcre_flags, &errcode, &erroffset, NULL);
	    if (!(*e)->code) {
		PCRE2_UCHAR buffer[256];
		pcre2_get_error_message(errcode, buffer, sizeof(buffer));
		parse_error(sym, "In PCRE2 expression /%s/ at offset %d: %s", sym->buf, erroffset, buffer);
	    }
	    (*e)->name = strdup(sym->buf);
	    tac_sym_get(sym);
	    (*e)->replacement = (PCRE2_SPTR) strdup(sym->buf);
	    e = &(*e)->next;
	    tac_sym_get(sym);
	}
#else
	parse_error(sym, "You're using a PCREv2-only feature, but this binary wasn't compiled with PCREv2 support.");
#endif
    }
    sym->flag_parse_pcre = 0;
    parse(sym, S_closebra);
}

static void parse_host(struct sym *sym, tac_realm * r)
{
    tac_host *host = (tac_host *) calloc(1, sizeof(tac_host));
    struct in6_addr a;
    int cm;
    radixtree_t *ht;

    host->line = sym->line;
    host->addrtree = radix_new(NULL, NULL);

    tac_sym_get(sym);

    if ((r == config.top_realm) && (sym->code == S_realm)) {
	tac_sym_get(sym);
	r = get_realm(sym->buf);
	tac_sym_get(sym);
    }
    host->realm = r;
    ht = r->hosttree;

    parse(sym, S_equal);

    if (v6_ptoh(&a, &cm, sym->buf)) {
	struct dns_forward_mapping *d;
	host->name = strdup(sym->buf);
	if (RB_lookup(hosttable, (void *) host))
	    parse_error(sym, "Host '%s' already defined", sym->buf);
	RB_insert(hosttable, host);

	d = dns_lookup_a(dns_tree_a, sym->buf);

	while (d) {
	    if (radix_add(ht, &d->a, cm, host))
		parse_error(sym, "Host '%s' already defined", sym->buf);
	    radix_add(host->addrtree, &d->a, cm, host);

	    d = d->next;
	}

    } else {
	if (radix_add(ht, &a, cm, host))
	    parse_error(sym, "Host '%s' already defined", sym->buf);
	radix_add(host->addrtree, &a, cm, host);
    }

    host->authen_max_attempts = -1;
    host->authfail_delay = -1;
    host->timeout = -1;
    host->dns_timeout = -1;

    tac_sym_get(sym);
    parse(sym, S_openbra);

    while (1)
	switch (sym->code) {
	case S_eof:
	    parse_error(sym, "EOF unexpected");
	case S_authentication:
	    tac_sym_get(sym);
	    switch (sym->code) {
	    case S_fallback:
		tac_sym_get(sym);
		parse(sym, S_equal);
		host->authfallback = parse_tristate(sym);
		break;
	    case S_realm:
		tac_sym_get(sym);
		parse(sym, S_equal);
		host->aaa_realm = get_realm(sym->buf);
		tac_sym_get(sym);
		break;
	    default:
		parse_error_expect(sym, S_fallback, S_realm, S_unknown);
	    }
	    continue;
	case S_permit:
	    tac_sym_get(sym);
	    parse(sym, S_ifauthenticated);
	    parse(sym, S_equal);
	    host->authz_if_authc = parse_tristate(sym);
	    continue;
	case S_access:
	    tac_sym_get(sym);
	    parse_host_acl(sym, &host->access_acl);
	    continue;
	case S_client:
	    tac_sym_get(sym);
	    switch (sym->code) {
	    case S_realm:
		tac_sym_get(sym);
		parse(sym, S_equal);
		host->nac_realm = get_realm(sym->buf);
		tac_sym_get(sym);
		break;
	    case S_bug:
		tac_sym_get(sym);
		parse(sym, S_equal);
		host->client_bug = parse_int(sym);
		break;
	    default:
		parse_error_expect(sym, S_bug, S_realm, S_unknown);
	    }
	    continue;
#ifdef SUPPORT_FOLLOW
	case S_follow:
	    tac_sym_get(sym);
	    parse(sym, S_equal);
	    if (host->follow && strcmp(host->follow, sym->buf))
		parse_error(sym, "Alternate daemon reference already set to '%s'", host->follow);
	    if (!host->follow)
		host->follow = strdup(sym->buf);
	    tac_sym_get(sym);
	    continue;
#endif
	case S_user:
	    tac_sym_get(sym);
	    switch (sym->code) {
	    case S_equal:
		tac_sym_get(sym);
		parse(sym, S_equal);
		if (host->username && strcmp(host->username, sym->buf))
		    parse_error(sym, "Default username already set to '%s'", host->username);
		if (!host->username)
		    host->username = strdup(sym->buf);
		tac_sym_get(sym);
		continue;
	    case S_realm:
		tac_sym_get(sym);
		parse(sym, S_equal);
		host->realm = get_realm(sym->buf);
		tac_sym_get(sym);
		continue;
	    default:
		parse_error_expect(sym, S_equal, S_realm, S_unknown);
	    }
	case S_default:
	    tac_sym_get(sym);
	    switch (sym->code) {
	    case S_user:
		tac_sym_get(sym);
		parse(sym, S_equal);
		if (host->username && strcmp(host->username, sym->buf))
		    parse_error(sym, "Default username already set to '%s'", host->username);
		if (!host->username)
		    host->username = strdup(sym->buf);
		tac_sym_get(sym);
		continue;
	    case S_group:
		tac_sym_get(sym);
		parse(sym, S_equal);
		if (host->groupname && strcmp(host->groupname, sym->buf))
		    parse_error(sym, "Default groupname already set to '%s'", host->groupname);
		if (!host->groupname)
		    host->groupname = strdup(sym->buf);
		tac_sym_get(sym);
		continue;
	    default:
		parse_error_expect(sym, S_user, S_group, S_unknown);
	    }
	case S_aaa:
	    tac_sym_get(sym);
	    switch (sym->code) {
	    case S_realm:
		tac_sym_get(sym);
		parse(sym, S_equal);
		host->aaa_realm = get_realm(sym->buf);
		tac_sym_get(sym);
		continue;
	    default:
		parse_error_expect(sym, S_realm, S_unknown);
	    }
	case S_pap:
	    tac_sym_get(sym);
	    switch (sym->code) {
	    case S_password:
		tac_sym_get(sym);
		parse(sym, S_mapping);
		parse(sym, S_equal);
		switch (sym->code) {
		case S_pap:
		    host->map_pap_to_login = TRISTATE_NO;
		    break;
		case S_login:
		    host->map_pap_to_login = TRISTATE_YES;
		    break;
		default:
		    parse_error_expect(sym, S_login, S_pap, S_unknown);
		}
		tac_sym_get(sym);
		continue;
	    default:
		parse_error_expect(sym, S_password, S_unknown);
	    }
	case S_password:
	    tac_sym_get(sym);
	    switch (sym->code) {
	    case S_maxattempts:
		tac_sym_get(sym);
		parse(sym, S_equal);
		host->authen_max_attempts = parse_int(sym);
		continue;
	    case S_backoff:
		tac_sym_get(sym);
		parse(sym, S_equal);
		host->authfail_delay = parse_seconds(sym);
		continue;
	    default:
		parse_error_expect(sym, S_maxattempts, S_backoff, S_unknown);
	    }
	case S_name:
	    if (host->name && strcmp(host->name, sym->buf))
		parse_error(sym, "Host name already set to '%s'", host->name);
	    tac_sym_get(sym);
	    parse(sym, S_equal);
	    if (!host->name) {
		host->name = strdup(sym->buf);
		if (RB_lookup(hosttable, (void *) host))
		    parse_error(sym, "Host '%s' already defined", sym->buf);
		RB_insert(hosttable, host);
	    }
	    tac_sym_get(sym);
	    continue;
	case S_alias:
	    report(NULL, LOG_ERR, ~0, "%s:%u: \"%s\" keyword is deprecated, use \"address\" " "instead", sym->filename, sym->line, sym->buf);
	case S_address:
	    tac_sym_get(sym);
	    if (sym->code == S_eof)
		parse_error(sym, "EOF unexpected");
	    if (sym->code == S_file) {
		glob_t globbuf;
		int i;

		memset(&globbuf, 0, sizeof(globbuf));
		tac_sym_get(sym);
		parse(sym, S_equal);

		globerror_sym = sym;

		switch (glob(sym->buf, GLOB_ERR | GLOB_NOESCAPE | GLOB_NOMAGIC | GLOB_BRACE, globerror, &globbuf)) {
		case 0:
		    parse_file_data.host = host;
		    for (i = 0; i < (int) globbuf.gl_pathc; i++)
			parse_file(globbuf.gl_pathv[i], ht);
		    break;
#ifdef GLOB_NOMATCH
		case GLOB_NOMATCH:
		    globerror(sym->buf, ENOENT);
		    break;
#endif				/* GLOB_NOMATCH */
		default:
		    parse_file_data.host = host;
		    parse_file(sym->buf, ht);
		    globfree(&globbuf);
		}
		tac_sym_get(sym);
	    } else {
		parse(sym, S_equal);
		do {
		    add_host(sym, ht, host);
		    tac_sym_get(sym);
		}
		while (parse_comma(sym));
	    }
	    continue;
	case S_clone:
	case S_template:
	    {
		tac_host *n, h;
		int i;

		tac_sym_get(sym);
		parse(sym, S_equal);
		h.name = sym->buf;
		n = (tac_host *) RB_lookup(hosttable, &h);
		if (!n)
		    n = (tac_host *) radix_lookup_str(ht, sym->buf, NULL);
		if (!n)
		    parse_error(sym, "Host '%s' not found", sym->buf);
		if (!host->key) {
		    struct tac_key **tn = &n->key;
		    struct tac_key **th = &host->key;
		    while (*tn) {
			*th = calloc(1, sizeof(struct tac_key) + (*tn)->len);
			(*th)->len = (*tn)->len;
			strncpy((*th)->key, (*tn)->key, (*tn)->len);
			th = &(*th)->next;
			tn = &(*tn)->next;
		    }
		}
		if (!host->welcome_banner)
		    host->welcome_banner = n->welcome_banner;
		if (!host->reject_banner)
		    host->reject_banner = n->reject_banner;
		if (!host->authfail_banner)
		    host->authfail_banner = n->authfail_banner;
		if (!host->motd)
		    host->motd = n->motd;

		host->debug |= n->debug;
		if (host->anon_enable == TRISTATE_DUNNO)
		    host->anon_enable = n->anon_enable;
		if (host->augmented_enable == TRISTATE_DUNNO)
		    host->augmented_enable = n->augmented_enable;
		if (host->valid_for_nas == TRISTATE_DUNNO)
		    host->valid_for_nas = n->valid_for_nas;
		if (host->valid_for_nac == TRISTATE_DUNNO)
		    host->valid_for_nac = n->valid_for_nac;
		for (i = 0; i <= TAC_PLUS_PRIV_LVL_MAX; i++)
		    if (!host->enable[i]) {
			host->enable[i] = n->enable[i];
			host->enable_implied[i] = n->enable_implied[i];
		    }
		tac_sym_get(sym);
	    }
	    continue;
	case S_clientonly:
	    report(NULL, LOG_ERR, ~0, "%s:%u: \"%s\" keyword is deprecated, use \"usage\" " "instead", sym->filename, sym->line, sym->buf);
	    tac_sym_get(sym);
	    parse(sym, S_equal);
	    host->valid_for_nac = TRISTATE_YES;
	    host->valid_for_nas = parse_bool(sym) ? TRISTATE_NO : TRISTATE_YES;
	    continue;
	case S_content:
	    report(NULL, LOG_ERR, ~0, "%s:%u: \"%s\" keyword is deprecated, use \"usage\" " "instead", sym->filename, sym->line, sym->buf);
	case S_usage:
	    tac_sym_get(sym);
	    parse(sym, S_equal);
	    switch (sym->code) {
	    case S_none:
		host->valid_for_nas = TRISTATE_NO;
		host->valid_for_nac = TRISTATE_NO;
	    case S_groupmembership:
		ht = NULL;
		break;
	    case S_any:
	    case S_all:
		host->valid_for_nas = TRISTATE_YES;
		host->valid_for_nac = TRISTATE_YES;
		break;
	    case S_client:
		host->valid_for_nas = TRISTATE_NO;
		host->valid_for_nac = TRISTATE_YES;
		break;
	    case S_server:
		host->valid_for_nas = TRISTATE_YES;
		host->valid_for_nac = TRISTATE_NO;
		break;
	    default:
		parse_error_expect(sym, S_none, S_any, S_all, S_client, S_server, S_unknown);
	    }
	    tac_sym_get(sym);
	    continue;
	case S_inherit:
	    tac_sym_get(sym);
	    parse(sym, S_equal);
	    host->orphan = parse_bistate(sym);
	    continue;
	case S_key:
	    parse_key(sym, &host->key);
	    continue;
	case S_failed:
	    tac_sym_get(sym);
	    parse(sym, S_authentication);
	    parse(sym, S_banner);
	    parse(sym, S_equal);
	    host->authfail_banner = strdup(sym->buf);
	    tac_sym_get(sym);
	    continue;
	case S_motd:
	    tac_sym_get(sym);
	    parse(sym, S_banner);
	    parse(sym, S_equal);
	    host->motd = strdup(sym->buf);
	    tac_sym_get(sym);
	    continue;
	case S_welcome:
	    tac_sym_get(sym);
	    if (sym->code != S_banner)
		parse(sym, S_banner);
	case S_prompt:
	    tac_sym_get(sym);
	    if (sym->code == S_fallback) {
		tac_sym_get(sym);
		parse(sym, S_equal);
		host->welcome_banner_fallback = strdup(sym->buf);
	    } else {
		parse(sym, S_equal);
		host->welcome_banner = strdup(sym->buf);
	    }
	    tac_sym_get(sym);
	    continue;
	case S_reject:
	    tac_sym_get(sym);
	    parse(sym, S_banner);
	    parse(sym, S_equal);
	    host->reject_banner = strdup(sym->buf);
	    tac_sym_get(sym);
	    continue;
	case S_enable:
	    parse_enable(sym, NULL, host->enable, host->enable_implied);
	    continue;
	case S_anonenable:
	    tac_sym_get(sym);
	    parse(sym, S_equal);
	    host->anon_enable = parse_tristate(sym);
	    continue;
	case S_augmented_enable:
	    tac_sym_get(sym);
	    parse(sym, S_equal);
	    host->augmented_enable = parse_tristate(sym);
	    continue;
	case S_dns:
	    tac_sym_get(sym);
	    switch (sym->code) {
	    case S_timeout:
		tac_sym_get(sym);
		parse(sym, S_equal);
		host->dns_timeout = parse_seconds(sym);
		continue;
	    case S_reverselookup:
		tac_sym_get(sym);
		parse(sym, S_equal);
		host->lookup_revmap = parse_tristate(sym);
		continue;
	    default:
		parse_error_expect(sym, S_timeout, S_reverselookup, S_unknown);
	    }
	case S_singleconnection:
	    tac_sym_get(sym);
	    switch (sym->code) {
	    case S_mayclose:
		tac_sym_get(sym);
		parse(sym, S_equal);
		host->cleanup_when_idle = parse_tristate(sym);
		break;
	    case S_equal:
		tac_sym_get(sym);
		host->single_connection = parse_tristate(sym);
		break;
	    default:
		parse_error_expect(sym, S_mayclose, S_equal, S_unknown);
	    }
	    continue;
	case S_debug:
	    tac_sym_get(sym);
	    parse(sym, S_equal);
	    parse_debug(sym, &host->debug);
	    continue;
	case S_connection:
	    tac_sym_get(sym);
	    parse(sym, S_timeout);
	    parse(sym, S_equal);
	    host->timeout = parse_seconds(sym);
	    continue;
	case S_rewrite:{
		tac_rewrite *rewrite = alloca(sizeof(tac_rewrite));
		rewrite->name = sym->buf;
		tac_sym_get(sym);
		parse(sym, S_user);
		if (sym->code == S_equal)
		    tac_sym_get(sym);
		host->rewrite_user = RB_lookup(r->rewrite, rewrite);
		if (!host->rewrite_user)
		    parse_error(sym, "Rewrite set '%s' not found", sym->buf);
		tac_sym_get(sym);
		continue;
	    }
	case S_closebra:
	    tac_sym_get(sym);
	    return;
	default:
	    parse_error(sym, "Unrecognized keyword '%s'", sym->buf);
	}
}

static struct tac_acllist *eval_tac_acllist(tac_session * session, char *cmd, struct tac_acllist **al)
{
    while (*al) {
	if ((*al)->acl) {
	    switch (eval_tac_acl(session, cmd, (*al)->acl)) {
	    case S_permit:
		if ((*al)->negate)
		    break;
		return *al;
	    case S_deny:
		if ((*al)->negate)
		    return *al;
		break;
	    default:
		;
	    }
	} else
	    return (*al)->negate ? NULL : *al;
	al = &(*al)->next;
    }
    return NULL;
}

char *eval_taglist(tac_session * session, tac_user * user)
{
    struct tac_acllist *a = eval_tac_acllist(session, NULL, &user->tag_acl);
    return a ? a->u.tag : session->tag;
}

static void parse_tag(struct sym *sym, tac_user * user)
{
    struct tac_acllist **acltag = &user->tag_acl;
    tac_sym_get(sym);

    while (*acltag)
	acltag = &(*acltag)->next;
    *acltag = mempool_malloc(user->pool, sizeof(struct tac_acllist));

    if (sym->code == S_acl) {
	struct tac_acl *a = NULL;
	int negate;
	parse_acl_cond(sym, user, &a, &negate);
	if (negate)
	    (*acltag)->negate = 1;
	(*acltag)->acl = a;
    }
    parse(sym, S_equal);
    (*acltag)->u.tag = mempool_strdup(user->pool, sym->buf);
    tac_sym_get(sym);
}

static void parse_cmd(struct sym *sym, tac_user * user, struct node_svc *shell)
{
    struct node_cmd *cmd;
    int line = sym->line;
    size_t len;

    tac_sym_get(sym);
    parse(sym, S_equal);
    len = sizeof(struct node_cmd) + strlen(sym->buf);
    cmd = alloca(len);
    strcpy(cmd->name, sym->buf);
    lower(cmd->name);
    cmd = RB_lookup(shell->sub, cmd);
    if (!cmd) {
	cmd = mempool_malloc(user->pool, len);
	cmd->line = line;
	strcpy(cmd->name, sym->buf);
	RB_insert(shell->sub, cmd);
    }
    tac_sym_get(sym);
    if (sym->code == S_openbra) {
	tac_sym_get(sym);
	parse_cmd_matches(sym, user, cmd);
	parse(sym, S_closebra);
    }
}

static struct node_svc *add_svc(struct sym *sym, tac_user * user, rb_tree_t * rbt, char *name, enum token type, struct tac_acl *acl, u_int negate)
{
    size_t len = sizeof(struct node_svc) + strlen(name);
    struct node_svc *svc = alloca(len);
    struct node_svc *svcfound;
    struct node_svc **p = &svc;

    svc->type = type;
    strcpy(svc->name, name);
    svc = svcfound = RB_lookup(rbt, svc);
    if (svc) {
	while (*p && ((*p)->acl != acl || (*p)->negate != negate)) {
	    if (acl && !(*p)->acl)
		report(NULL, LOG_ERR, ~0,
		       "%s:%u: %s: ACL %s defined after global match, " "will be ignored.", sym->filename, sym->line, user->name, acl->name);
	    p = &(*p)->next;
	}
	if (*p)
	    return *p;
    }
    *p = mempool_malloc(user->pool, len);
    strcpy((*p)->name, name);
    (*p)->type = type;
    (*p)->acl = acl;
    (*p)->negate = negate ? 1 : 0;
    (*p)->attr_dflt = S_deny;
    (*p)->sub_dflt = S_unknown;
    (*p)->line = sym->line;
    if (!svcfound)
	RB_insert(rbt, *p);
    return *p;
}

static void parse_proto(struct sym *sym, tac_user * user, struct node_svc *svcp)
{
    struct node_svc *protp;

    tac_sym_get(sym);
    parse(sym, S_equal);
    protp = add_svc(sym, user, svcp->sub, sym->buf, sym->code, NULL, 0);
    tac_sym_get(sym);

    if (sym->code == S_openbra) {
	tac_sym_get(sym);
	parse_attrs(sym, user, protp);
	parse(sym, S_closebra);
    } else
	protp->attr_dflt = S_permit;
}

struct tac_acl_cache {
    struct tac_acl_cache *next;
    struct tac_acl *acl;
    enum token result;
};

static enum token tac_script_eval_r(tac_session *, char *, struct mavis_action *, char **);

static int match_regex(tac_session * session, void *, char *, enum tac_acl_type, char *);

enum token eval_tac_acl(tac_session * session, char *cmd, struct tac_acl *acl)
{
    if (acl) {
	char *hint = "";
	struct tac_acl_expr *r;
	enum token res = S_deny;
	struct tac_acl_cache **tc = &session->tac_acl_cache;
	while (*tc && (*tc)->acl != acl)
	    tc = &(*tc)->next;

	if (*tc) {
	    if ((*tc)->result == S_unknown) {
		hint = " (recursion detected)";
		report(session, LOG_ERR, ~0, "%s@%s: ACL %s: recursion detected, skipping", session->username, session->nac_address_ascii, acl->name);
	    } else
		hint = " (cached)";
	} else {
	    *tc = mempool_malloc(session->pool, sizeof(struct tac_acl_cache));
	    (*tc)->acl = acl;
	    (*tc)->result = S_unknown;

	    if (acl->action) {
		struct mavis_action *action = acl->action;
		while (action)
		    switch ((res = tac_script_eval_r(session, cmd, action, NULL))) {
		    case S_permit:
		    case S_deny:
			*tc = mempool_malloc(session->pool, sizeof(struct tac_acl_cache));
			(*tc)->acl = acl;
			(*tc)->result = res;
			return res;
		    default:
			action = action->n;
		    }
	    }

	    for (r = acl->expr; r; r = r->next) {
		int match = 0, skip = 0;

		if (r->nas) {
		    struct acl_element *e = r->nas;
		    while (e) {
			match = 0, skip = 0;
			tac_host **h;
			switch (e->type) {
			case T_cidr:
			    match = v6_contains(&e->blob.c->addr, e->blob.c->mask, &session->ctx->nas_address);
			    break;
			case T_host:
			    for (h = (session->ctx->hostchain); *h; h++) {
				if ((*h)->name) {
				    match = (*h == (tac_host *) (e->blob.h));
				    if (match)
					break;
				}
			    }
			    break;
			case T_regex_pcre:
			case T_regex_posix:
			    match = match_regex(session, e->blob.r, session->ctx->nas_address_ascii, e->type, e->string);
			    break;
			case T_dns_regex_pcre:
			    if (session->ctx->nas_dns_name && *session->ctx->nas_dns_name)
				match = match_regex(session, e->blob.r, session->ctx->nas_dns_name, T_regex_pcre, e->string);
			    else
				skip = 1;
			    break;
			case T_dns_regex_posix:
			    if (session->ctx->nas_dns_name && *session->ctx->nas_dns_name)
				match = match_regex(session, e->blob.r, session->ctx->nas_dns_name, T_regex_posix, e->string);
			    else
				skip = 1;
			    break;
			default:
			    ;
			}
			report(session, LOG_DEBUG,
			       DEBUG_ACL_FLAG | DEBUG_REGEX_FLAG,
			       "%s@%s: ACL %s line %u: %s \"%s\" <=> %s\"%s\"%s",
			       session->username,
			       session->nac_address_ascii, acl->name, (u_int) e->line, "NAS", (e->type == T_dns_regex_pcre || e->type == T_dns_regex_pcre)
			       ? (session->ctx->nas_dns_name ? session->ctx->nas_dns_name : "(not found)")
			       : session->ctx->nas_address_ascii, e->negate ? "not " : "", e->string, skip ? ", skipping" : "");
			if (e->negate)
			    match = !match;
			if (match && !skip)
			    break;
			match = 0;
			e = e->next;
		    }
		    if (!match)
			continue;
		}

		report(session, LOG_DEBUG,
		       DEBUG_ACL_FLAG | DEBUG_REGEX_FLAG,
		       "%s@%s: ACL %s: %s matched%s", session->username, session->nac_address_ascii, acl->name, "NAS", r->nas ? "" : " (unrestricted)");

		match = 0;

		if (r->nac) {
		    struct acl_element *e = r->nac;
		    while (e) {
			match = 0, skip = 0;
			switch (e->type) {
			case T_cidr:
			    if (session->nac_address_valid)
				match = v6_contains(&e->blob.c->addr, e->blob.c->mask, &session->nac_address);
			    break;
			case T_host:
			    if (session->nac_address_valid)
				match = radix_lookup(e->blob.h->addrtree, &session->nac_address, NULL) ? -1 : 0;
			    break;
			case T_regex_pcre:
			case T_regex_posix:
			    match = match_regex(session, e->blob.r, session->nac_address_ascii, e->type, e->string);
			    break;
			case T_dns_regex_pcre:
			    if (session->nac_dns_name && *session->nac_dns_name)
				match = match_regex(session, e->blob.r, session->nac_dns_name, T_regex_pcre, e->string);
			    else
				skip = 1;
			    break;
			case T_dns_regex_posix:
			    if (session->nac_dns_name && *session->nac_dns_name)
				match = match_regex(session, e->blob.r, session->nac_dns_name, T_regex_posix, e->string);
			    else
				skip = 1;
			    break;
			default:
			    ;
			}
			report(session, LOG_DEBUG,
			       DEBUG_ACL_FLAG | DEBUG_REGEX_FLAG,
			       "%s@%s: ACL %s line %u: %s \"%s\" <=> %s\"%s\"%s",
			       session->username,
			       session->nac_address_ascii, acl->name, (u_int) e->line, "NAC", (e->type == T_dns_regex_pcre || e->type == T_dns_regex_posix)
			       ? (session->nac_dns_name ? session->nac_dns_name : "(not found)")
			       : session->nac_address_ascii, e->negate ? "not " : "", e->string, skip ? ", skipping" : "");
			if (e->negate)
			    match = !match;
			if (match && !skip)
			    break;
			match = 0;
			e = e->next;
		    }
		    if (!match)
			continue;
		}
		report(session, LOG_DEBUG,
		       DEBUG_ACL_FLAG | DEBUG_REGEX_FLAG,
		       "%s@%s: ACL %s: %s matched%s", session->username, session->nac_address_ascii, acl->name, "NAC", r->nac ? "" : " (unrestricted)");

		match = 0;

		if (r->port) {
		    struct acl_element *e = r->port;
		    while (e) {
			match = match_regex(session, e->blob.r, session->nas_port, e->type, e->string);

			report(session, LOG_DEBUG,
			       DEBUG_ACL_FLAG | DEBUG_REGEX_FLAG,
			       "%s@%s: ACL %s line %u: %s \"%s\" <=> %s\"%s\"",
			       session->username,
			       session->nac_address_ascii, acl->name, (u_int) e->line, "Port", session->nas_port, e->negate ? "not" : "", e->string);
			if (e->negate)
			    match = !match;
			if (match)
			    break;
			e = e->next;
		    }
		    if (!match)
			continue;
		}

		report(session, LOG_DEBUG,
		       DEBUG_ACL_FLAG | DEBUG_REGEX_FLAG,
		       "%s@%s: ACL %s: %s matched%s", session->username, session->nac_address_ascii, acl->name, "Port", r->port ? "" : " (unrestricted)");

		match = 0;

		if (r->realm) {
		    struct acl_element *e = r->realm;
		    while (e) {
			char *realmname = NULL;
			switch (e->type) {
			case T_regex_pcre:
			case T_regex_posix:
			    match = match_regex(session, e->blob.r, session->ctx->aaa_realm->name, e->type, e->string);
			    realmname = e->string;
			    break;
			case T_realm:
			    match = (e->blob.m == session->ctx->aaa_realm);
			    realmname = e->blob.m->name;
			    break;
			default:
			    ;
			}
			report(session, LOG_DEBUG,
			       DEBUG_ACL_FLAG | DEBUG_REGEX_FLAG,
			       "%s@%s: ACL %s line %u: %s \"%s\" <=> %s\"%s\"",
			       session->username,
			       session->nac_address_ascii, acl->name, (u_int) e->line, "Realm", session->ctx->aaa_realm->name, e->negate ? "not" : "",
			       realmname);
			if (e->negate)
			    match = !match;
			if (match)
			    break;
			e = e->next;
		    }
		    if (!match)
			continue;
		}

		report(session, LOG_DEBUG,
		       DEBUG_ACL_FLAG | DEBUG_REGEX_FLAG,
		       "%s@%s: ACL %s: %s matched%s", session->username, session->nac_address_ascii, acl->name, "Realm", r->realm ? "" : " (unrestricted)");

		match = 0;

		if (r->time) {
		    struct acl_element *e = r->time;

		    while (e) {
			char *cronstring = NULL;
			match = eval_timespec((struct mavis_timespec *) (e->blob.t), &cronstring);
			report(session, LOG_DEBUG,
			       DEBUG_ACL_FLAG | DEBUG_REGEX_FLAG,
			       "%s@%s: ACL %s line %u: %s %s\"%s\"%s%s%s",
			       session->username,
			       session->nac_address_ascii, acl->name,
			       (u_int) e->line, "Timespec",
			       e->negate ? "not " : "", e->string, cronstring ? " (" : "", cronstring ? cronstring : "", cronstring ? ")" : "");
			if (e->negate)
			    match = !match;
			if (match)
			    break;
			e = e->next;
		    }
		    if (!match)
			continue;

		}

		report(session, LOG_DEBUG,
		       DEBUG_ACL_FLAG | DEBUG_REGEX_FLAG,
		       "%s@%s: ACL %s: %s matched%s", session->username, session->nac_address_ascii, acl->name, "Timespec", r->time ? "" : " (unrestricted)");

		match = 0;

		if (r->acl) {
		    struct acl_element *e = r->acl;

		    while (e) {
			match = S_permit == eval_tac_acl(session, cmd, e->blob.a);
			report(session, LOG_DEBUG,
			       DEBUG_ACL_FLAG | DEBUG_REGEX_FLAG,
			       "%s@%s: ACL %s line %u: %s %s%s",
			       session->username, session->nac_address_ascii, acl->name, (u_int) e->line, "ACL", e->negate ? "not " : "", e->string);
			if (e->negate)
			    match = !match;
			if (match)
			    break;
			e = e->next;
		    }
		    if (!match)
			continue;

		}
		report(session, LOG_DEBUG,
		       DEBUG_ACL_FLAG | DEBUG_REGEX_FLAG,
		       "%s@%s: ACL %s: %s matched%s", session->username, session->nac_address_ascii, acl->name, "ACL", r->acl ? "" : " (unrestricted)");

		res = r->negate ? S_deny : S_permit;
		break;		/* for */
	    }			/* for */
	    (*tc)->result = res;
	}

	report(session, LOG_DEBUG,
	       DEBUG_ACL_FLAG | DEBUG_REGEX_FLAG,
	       "%s@%s: ACL %s: %smatch%s", session->username, session->nac_address_ascii, acl->name, (*tc)->result == S_permit ? "" : "no ", hint);

	return (*tc)->result == S_unknown ? S_deny : (*tc)->result;
    }
    return S_permit;
}

static void parse_tac_acl_expr(struct sym *sym, struct tac_acl_expr **e, int negate)
{
    struct acl_element **r;

    tac_host h, *hp;

    *e = calloc(1, sizeof(struct tac_acl_expr));

    (*e)->negate = negate;

    while (1) {
	int check_dns = 0;

	switch (sym->code) {
	case S_eof:
	    parse_error(sym, "EOF unexpected");
	case S_closebra:
	    return;
	case S_nac:
	    check_dns++;
	case S_nacname:
	    r = &(*e)->nac;
	    goto XXX;
	case S_nas:
	    check_dns++;
	case S_nasname:
	    r = &(*e)->nas;
	  XXX:
	    tac_sym_get(sym);
	    if (check_dns && sym->code == S_dns) {
		tac_sym_get(sym);
		check_dns++;
	    }
	    while (*r)
		r = &(*r)->next;
	    *r = calloc(1, sizeof(struct acl_element));
	    (*r)->line = sym->line;
	    switch (sym->code) {
	    case S_exclmark:
		(*r)->negate = 1;
		tac_sym_get(sym);
		switch (sym->code) {
		case S_equal:
		    tac_sym_get(sym);
		    goto mark_string;
		case S_tilde:
		    sym->flag_parse_pcre = 1;
		    tac_sym_get(sym);
		    goto mark_regex;
		default:
		    parse_error_expect(sym, S_equal, S_tilde, S_unknown);
		}
	    case S_equal:
		tac_sym_get(sym);
		switch (sym->code) {
		case S_equal:
		    tac_sym_get(sym);
		    goto mark_string;
		case S_tilde:
		    sym->flag_parse_pcre = 1;
		    tac_sym_get(sym);
		    goto mark_regex;
		case S_not:
		    (*r)->negate = 1;
		    tac_sym_get(sym);
		    break;
		default:;
		}
	      mark_string:
		h.name = sym->buf;
		hp = RB_lookup(hosttable, (void *) &h);
		if (hp) {
		    (*r)->type = T_host;
		    (*r)->string = strdup(sym->buf);
		    (*r)->blob.h = hp;
		} else {
		    (*r)->blob.c = calloc(1, sizeof(struct in6_cidr));
		    if (v6_ptoh(&(*r)->blob.c->addr, &(*r)->blob.c->mask, sym->buf))
			parse_error(sym, "Expected a hostname or an IP " "address/network in CIDR notation, " "but got '%s'.", sym->buf);
		    (*r)->type = T_cidr;
		    (*r)->string = strdup(sym->buf);
		}
		tac_sym_get(sym);
		break;
	    case S_regex:
		sym->flag_parse_pcre = 1;
		tac_sym_get(sym);
		parse(sym, S_equal);
		if (sym->code == S_not) {
		    (*r)->negate = 1;
		    tac_sym_get(sym);
		}
	      mark_regex:
		(*r)->string = strdup(sym->buf);
		(*r)->type = parse_aclregex(sym, *r);
		if (check_dns == 2) {
		    if ((*r)->type == T_regex_pcre)
			(*r)->type = T_dns_regex_pcre;
		    else if ((*r)->type == T_regex_posix)
			(*r)->type = T_dns_regex_posix;
		}
		sym->flag_parse_pcre = 0;
		break;
	    default:
		parse_error_expect(sym, S_equal, S_name, S_regex, S_unknown);
	    }
	    break;
	case S_port:
	    sym->flag_parse_pcre = 1;
	    tac_sym_get(sym);
	    r = &(*e)->port;
	    while (*r)
		r = &(*r)->next;
	    *r = calloc(1, sizeof(struct acl_element));
	    (*r)->line = sym->line;
	    switch (sym->code) {
	    case S_exclmark:
		(*r)->negate = 1;
	    case S_equal:
		tac_sym_get(sym);
		break;
	    case S_regex:
		tac_sym_get(sym);
		parse(sym, S_equal);
		if (sym->code == S_not) {
		    (*r)->negate = 1;
		    tac_sym_get(sym);
		}
		break;
	    default:
		parse_error_expect(sym, S_exclmark, S_equal, S_regex, S_unknown);
	    }
	    (*r)->string = strdup(sym->buf);
	    (*r)->type = parse_aclregex(sym, *r);
	    sym->flag_parse_pcre = 0;
	    break;
	case S_realm:
	    sym->flag_parse_pcre = 1;
	    tac_sym_get(sym);
	    r = &(*e)->realm;
	    while (*r)
		r = &(*r)->next;
	    *r = calloc(1, sizeof(struct acl_element));
	    (*r)->line = sym->line;
	    switch (sym->code) {
	    case S_exclmark:
		(*r)->negate = 1;
	    case S_equal:
		tac_sym_get(sym);
		(*r)->type = T_realm;
		(*r)->blob.m = get_realm(sym->buf);
		tac_sym_get(sym);
		break;
	    case S_regex:
		tac_sym_get(sym);
		parse(sym, S_equal);
		if (sym->code == S_not) {
		    (*r)->negate = 1;
		    tac_sym_get(sym);
		}
		(*r)->type = parse_aclregex(sym, *r);
		break;
	    default:
		parse_error_expect(sym, S_exclmark, S_equal, S_regex, S_unknown);
	    }
	    (*r)->string = strdup(sym->buf);
	    sym->flag_parse_pcre = 0;
	    break;
	case S_acl:
	    tac_sym_get(sym);
	    r = &(*e)->acl;
	    while (*r)
		r = &(*r)->next;
	    *r = calloc(1, sizeof(struct acl_element));
	    (*r)->line = sym->line;
	    switch (sym->code) {
	    case S_equal:
		tac_sym_get(sym);
		if (sym->code == S_not) {
		    (*r)->negate = 1;
		    tac_sym_get(sym);
		}
		break;
	    case S_exclmark:
		tac_sym_get(sym);
		parse(sym, S_equal);
		break;
	    default:
		parse_error_expect(sym, S_equal, S_exclmark, S_unknown);
	    }

	    (*r)->blob.a = tac_acl_lookup(sym->buf);
	    if (!(*r)->blob.a)
		parse_error(sym, "ACL '%s' not found", sym->buf);
	    (*r)->string = strdup(sym->buf);
	    tac_sym_get(sym);
	    break;
	case S_time:
	    tac_sym_get(sym);
	    r = &(*e)->time;
	    while (*r)
		r = &(*r)->next;
	    *r = calloc(1, sizeof(struct acl_element));
	    (*r)->line = sym->line;
	    switch (sym->code) {
	    case S_equal:
		tac_sym_get(sym);
		if (sym->code == S_not) {
		    (*r)->negate = 1;
		    tac_sym_get(sym);
		}
		break;
	    case S_exclmark:
		tac_sym_get(sym);
		parse(sym, S_equal);
		break;
	    default:
		parse_error_expect(sym, S_equal, S_exclmark, S_unknown);
	    }
	    (*r)->string = strdup(sym->buf);
	    (*r)->blob.t = find_timespec(timespectable, sym->buf);
	    if (!(*r)->blob.t)
		parse_error(sym, "timespec '%s' not found", sym->buf);
	    tac_sym_get(sym);
	    break;
	default:
	    parse_error_expect(sym, S_nac, S_nas, S_port, S_time, S_acl, S_unknown);
	}
    }
}

static struct mavis_action *tac_script_parse_r(tac_user *, struct sym *, int);

// acl = <name> [(permit|deny)] { ... }
static void parse_tac_acl(struct sym *sym)
{
    struct tac_acl *a;
    int is_script = 0;
    int negate = 0;
    tac_sym_get(sym);

    if (sym->code == S_script) {
	is_script++;
	tac_sym_get(sym);
    }

    parse(sym, S_equal);

    a = tac_acl_lookup(sym->buf);
    if (!a) {
	size_t l = strlen(sym->buf);
	a = calloc(1, sizeof(struct tac_acl) + l);
	strcpy(a->name, sym->buf);
	RB_insert(acltable, a);
    }
    tac_sym_get(sym);

    switch (sym->code) {
    case S_deny:
	negate = 1;
    case S_permit:
	tac_sym_get(sym);
    case S_openbra:
	break;
    default:
	parse_error_expect(sym, S_permit, S_deny, S_openbra, S_unknown);
    }
    parse(sym, S_openbra);

    if (is_script) {
	struct mavis_action **p = &a->action;

	while (*p)
	    p = &(*p)->n;

	*p = tac_script_parse_r(NULL, sym, 1);
    } else {
	struct tac_acl_expr **e = &a->expr;
	while (*e)
	    e = &((*e)->next);

	parse_tac_acl_expr(sym, e, negate);
    }

    parse(sym, S_closebra);
}

static void parse_svcs(struct sym *sym, tac_user * user)
{
    struct node_svc *svcp;
    struct tac_acl *a = NULL;
    int negate = 0;

    tac_sym_get(sym);

    parse_acl_cond(sym, user, &a, &negate);
    parse(sym, S_equal);

    if (sym->code == S_string && !strncmp(sym->buf, "shell@", 6))
	sym->code = S_shell;

    svcp = add_svc(sym, user, user->svcs, sym->buf, sym->code, a, negate);

    if (!svcp->sub)
	svcp->sub = (sym->code == S_shell)
	    ? RB_tree_new(compare_cmd, NULL) : RB_tree_new(compare_svc, NULL);

    tac_sym_get(sym);

    if (sym->code == S_openbra) {
	tac_sym_get(sym);
	parse_attrs(sym, user, svcp);
	parse(sym, S_closebra);
    } else {
	svcp->sub_dflt = S_permit;
	svcp->attr_dflt = S_permit;
    }
}

static enum tac_acl_type parse_regex(struct sym *sym, tac_user * user, void **rptr)
{
    int errcode = 0;
    if (sym->code == S_slash) {
#ifdef WITH_PCRE2
	PCRE2_SIZE erroffset;
	*rptr = pcre2_compile((PCRE2_SPTR8) sym->buf, PCRE2_ZERO_TERMINATED, PCRE2_MULTILINE | common_data.regex_pcre_flags, &errcode, &erroffset, NULL);
	if (*rptr) {
	    if (user->pool_pcre)
		RB_insert(user->pool_pcre, *rptr);
	} else {
	    PCRE2_UCHAR buffer[256];
	    pcre2_get_error_message(errcode, buffer, sizeof(buffer));
	    parse_error(sym, "In PCRE2 expression /%s/ at offset %d: %s", sym->buf, erroffset, buffer);
	}
	tac_sym_get(sym);
	return T_regex_pcre;
#else
	parse_error(sym, "You're using PCRE2 syntax, but this binary wasn't compiled with PCRE2 support.");
#endif
    }
    *rptr = mempool_malloc(user->pool, sizeof(regex_t));
    errcode = regcomp((regex_t *) * rptr, sym->buf, REG_EXTENDED | REG_NOSUB | REG_NEWLINE | common_data.regex_posix_flags);
    if (errcode) {
	char e[160];
	regerror(errcode, (regex_t *) * rptr, e, sizeof(e));
	parse_error(sym, "In regular expression '%s': %s", sym->buf, e);
	mempool_free(user->pool, (regex_t *) * rptr);
    } else if (user->pool_regex)
	RB_insert(user->pool_regex, *rptr);
    tac_sym_get(sym);
    return T_regex_posix;
}

static enum tac_acl_type parse_aclregex(struct sym *sym, struct acl_element *ae)
{
    int errcode = 0;
    if (sym->code == S_slash) {
#ifdef WITH_PCRE2
	PCRE2_SIZE erroffset;
	ae->blob.p = pcre2_compile((PCRE2_SPTR8) sym->buf, PCRE2_ZERO_TERMINATED, PCRE2_MULTILINE | common_data.regex_pcre_flags, &errcode, &erroffset, NULL);
	if (!ae->blob.p) {
	    PCRE2_UCHAR buffer[256];
	    pcre2_get_error_message(errcode, buffer, sizeof(buffer));
	    parse_error(sym, "In PCRE2 expression /%s/ at offset %d: %s", sym->buf, erroffset, buffer);
	}
	tac_sym_get(sym);
	return T_regex_pcre;
#else
	parse_error(sym, "You're using PCRE2 syntax, but this binary wasn't compiled with PCRE2 support.");
#endif
    }
    ae->blob.r = calloc(1, sizeof(regex_t));
    errcode = regcomp(ae->blob.r, sym->buf, REG_EXTENDED | REG_NOSUB | REG_NEWLINE | common_data.regex_posix_flags);
    if (errcode) {
	char e[160];
	regerror(errcode, ae->blob.r, e, sizeof(e));
	parse_error(sym, "In regular expression '%s': %s", sym->buf, e);
    }
    tac_sym_get(sym);
    return T_regex_posix;
}

/* <cmd-match>	 := <permission> <string> */

static void parse_cmd_matches(struct sym *sym, tac_user * user, struct node_cmd *cmd)
{
    struct node_perm **np = &cmd->perm;
    enum token perm;
    int line = sym->line;

    while (*np)
	np = &(*np)->next;

    sym->flag_parse_pcre = 1;
    while (1) {
	switch (sym->code) {
	case S_permit:
	case S_deny:
	    perm = parse_permission(sym);
	    (*np) = mempool_malloc(user->pool, sizeof(struct node_perm) + strlen(sym->buf));
	    (*np)->line = line;
	    (*np)->type = perm;
	    strcpy((*np)->name, sym->buf);
	    (*np)->regex_type = parse_regex(sym, user, &((*np)->regex));
	    np = &(*np)->next;
	    continue;
	case S_message:{
		char **m = NULL;
		tac_sym_get(sym);
		switch (sym->code) {
		case S_debug:
		    m = &cmd->msg_debug;
		    break;
		case S_permit:
		    m = &cmd->msg_permit;
		    break;
		case S_deny:
		    m = &cmd->msg_deny;
		    break;
		default:
		    parse_error_expect(sym, S_debug, S_deny, S_permit, S_unknown);
		}
		tac_sym_get(sym);
		parse(sym, S_equal);
		if (m)
		    *m = mempool_strdup(user->pool, sym->buf);
		tac_sym_get(sym);
		continue;
	    }
	default:
	    break;
	}
	break;
    }
    sym->flag_parse_pcre = 0;
}

static void attr_add(tac_user * user, char ***v, int *i, char *attr, char *sep, char *q1, char *value, char *q2)
{
    char *s;
    size_t len;
    size_t attr_len = strlen(attr);
    size_t sep_len = strlen(sep);
    size_t q1_len = strlen(q1);
    size_t value_len = strlen(value);
    size_t q2_len = strlen(q2);

    if (!(*i & 0xf)) {
	char **v_new = mempool_malloc(user->pool, (*i + 16) * sizeof(char *));
	if (*i)
	    memcpy(v_new, *v, *i * sizeof(char *));
	mempool_free(user->pool, v);
	*v = v_new;
    }
    len = attr_len + sep_len + q1_len + value_len + q2_len + 1;
    s = mempool_malloc(user->pool, len);
    (*v)[(*i)++] = s;
    memcpy(s, attr, attr_len);
    s += attr_len;
    memcpy(s, sep, sep_len);
    s += sep_len;
    memcpy(s, q1, q1_len);
    s += q1_len;
    memcpy(s, value, value_len);
    s += value_len;
    memcpy(s, q2, q2_len);
}

static void tac_script_parse(tac_user *, struct node_svc *, struct sym *);

static void parse_attrs(struct sym *sym, tac_user * user, struct node_svc *svc)
{
    enum token sc;
    int double_quote_values = 0;

    while (sym->code != S_closebra && sym->code != S_eof) {
	char *sep, *attr, *quote;
	sep = "=";
	quote = double_quote_values ? "\"" : "";

	switch ((sc = sym->code)) {
	case S_double_quote_values:
	    tac_sym_get(sym);
	    parse(sym, S_equal);
	    double_quote_values = parse_bool(sym);
	    continue;
	case S_default:
	    tac_sym_get(sym);
	    if (svc->sub && sym->code == S_protocol && svc->type != S_shell) {
		tac_sym_get(sym);
		parse(sym, S_equal);
		svc->sub_dflt = parse_permission(sym);
	    } else if (svc->sub && (sym->code == S_cmd || sym->code == S_command) && svc->type == S_shell) {
		tac_sym_get(sym);
		parse(sym, S_equal);
		svc->sub_dflt = parse_permission(sym);
	    } else if (sym->code == S_attr) {
		tac_sym_get(sym);
		parse(sym, S_equal);
		svc->attr_dflt = parse_permission(sym);
	    }
	    continue;
	case S_acl:
	    parse_user_acl(sym, user, &svc->acllist);
	    continue;
	case S_return:
	    tac_sym_get(sym);
	    svc->final = 1;
	    continue;
	case S_message:{
		char **m = NULL;
		tac_sym_get(sym);
		switch (sym->code) {
		case S_debug:
		    m = &svc->msg_debug;
		    break;
		case S_permit:
		    m = &svc->msg_permit;
		    break;
		case S_deny:
		    m = &svc->msg_deny;
		    break;
		default:
		    parse_error_expect(sym, S_debug, S_deny, S_permit, S_unknown);
		}
		tac_sym_get(sym);
		parse(sym, S_equal);
		if (m)
		    *m = mempool_strdup(user->pool, sym->buf);
		tac_sym_get(sym);
		continue;
	    }
	case S_add:
	case S_optional:
	    sep = "*";
	case S_set:
	    tac_sym_get(sym);
	    attr = strdup(sym->buf);
	    tac_sym_get(sym);
	    parse(sym, S_equal);

	    if (sc == S_set)
		attr_add(user, &svc->attrs_m, &svc->cnt_m, attr, sep, quote, sym->buf, quote);
	    else if (sc == S_add)
		attr_add(user, &svc->attrs_a, &svc->cnt_a, attr, sep, quote, sym->buf, quote);
	    else		// S_optional
		attr_add(user, &svc->attrs_o, &svc->cnt_o, attr, sep, quote, sym->buf, quote);

	    tac_sym_get(sym);
	    free(attr);
	    continue;
	case S_protocol:
	    if (svc->sub && svc->type != S_shell) {
		parse_proto(sym, user, svc);
		continue;
	    }
	    break;
	case S_cmd:
	case S_command:
	    if (svc->sub && svc->type == S_shell) {
		parse_cmd(sym, user, svc);
		continue;
	    }
	    break;
	case S_script:
	    tac_script_parse(user, svc, sym);
	    continue;
	default:
	    break;
	}
	if (svc->sub && svc->type == S_shell)
	    parse_error_expect(sym, S_acl, S_command, S_cmd, S_default, S_double_quote_values, S_message, S_optional, S_return, S_script, S_set, S_unknown);
	else
	    parse_error_expect(sym, S_acl, S_default, S_double_quote_values, S_message, S_optional, S_protocol, S_return, S_script, S_set, S_unknown);
    }
}

void cfg_init(void)
{
    hosttable = RB_tree_new(compare_host, NULL);
    acltable = RB_tree_new(compare_acl, NULL);
    timespectable = init_timespec();
    memset(&config, 0, sizeof(struct config));
    config.realms = RB_tree_new(compare_realm, NULL);
    config.mask = 0644;
    config.dns_caching_period = 8 * 3600 / 2;
    config.top_realm = get_realm(NULL);
    config.default_realm = config.top_realm;
    config.top_realm->shellctx_expire = 3600;
    config.top_realm->timeout = 600;
    config.top_realm->session_timeout = 240;
    config.top_realm->caching_period = 120;
    config.top_realm->warning_period = 86400 * 14;
    config.top_realm->separator = '*';
    config.top_realm->anon_enable = TRISTATE_YES;
    config.top_realm->augmented_enable = TRISTATE_NO;
    config.top_realm->authen_max_attempts = -1;
    config.top_realm->authfail_delay = -1;
    config.top_realm->date_format = "%Y-%m-%d %H:%M:%S %z";
    config.top_realm->log_separator = "\t";
    config.top_realm->log_separator_len = 1;
    config.top_realm->authfallback = TRISTATE_YES;
    config.top_realm->single_connection = TRISTATE_YES;
    config.top_realm->cleanup_when_idle = TRISTATE_NO;
    config.top_realm->backend_failure_period = 60;
    config.top_realm->skip_missing_groups = 0;
    config.top_realm->skip_conflicting_groups = 0;
    config.top_realm->debug = common_data.debug;
    config.top_realm->nac_realm = config.top_realm;
    config.top_realm->aaa_realm = config.top_realm;
    config.top_realm->group_realm = config.top_realm;
    config.logfiles = RB_tree_new(compare_log, NULL);
    config.top_realm->debug = common_data.debug;
    config.log_matched_group = 0;

    {
	char *acl = "acl script = __internal__enable_user__ " "{ if (user =~ \"^\\\\$enab..?\\\\$$\") permit deny }";
	struct sym sym;
	memset(&sym, 0, sizeof(sym));
	sym.filename = "__internal__";
	sym.line = 1;
	sym.in = sym.tin = acl;
	sym.len = sym.tlen = strlen(acl);
	sym_init(&sym);
	parse_tac_acl(&sym);
	config.top_realm->enable_user_acl = tac_acl_lookup("__internal__enable_user__");
    }

    {
	struct utsname utsname;
	memset(&utsname, 0, sizeof(struct utsname));
	if (uname(&utsname) || !*(utsname.nodename))
	    config.hostname = "amnesiac";
	else
	    config.hostname = strdup(utsname.nodename);
    }

    {
	char *e = "051207055A0A070E204D4F08180416130A0D052B2A2529323423120617020057585952550F021917585956525354550A5A07065956";
	char *u, *t = e;

	config.c7xlat = calloc(1, strlen(e) / 2 + 1);
	u = config.c7xlat;
	while (*t) {
	    *u = 'a' ^ hexbyte(t);
	    u++, t += 2;
	}
	config.c7xlat_len = strlen(config.c7xlat);
    }
    passwd_deny = calloc(1, sizeof(struct pwdat));
    passwd_deny->type = S_deny;
    passwd_mavis = calloc(1, sizeof(struct pwdat));
    passwd_mavis->type = S_mavis;
    passwd_login = calloc(1, sizeof(struct pwdat));
    passwd_login->type = S_login;
    passwd_deny_dflt = calloc(1, sizeof(struct pwdat));
    passwd_deny_dflt->type = S_deny;
    passwd_mavis_dflt = calloc(1, sizeof(struct pwdat));
    passwd_mavis_dflt->type = S_mavis;
    passwd_login_dflt = calloc(1, sizeof(struct pwdat));
    passwd_login_dflt->type = S_login;
    passwd_permit = calloc(1, sizeof(struct pwdat));
    passwd_permit->type = S_permit;
}

static tac_user *member_lookup(tac_session * session, radixtree_t * t, char *tag)
{
    tac_user *g, **ga;

    struct groups_s *gs = radix_lookup(t, &session->ctx->nas_address, NULL);

    if (!gs)
	return NULL;

    ga = gs->g;

    if (!ga)
	return NULL;

    g = *ga;

    if (tag)
	while (*ga && strcmp((*ga)->name, tag))
	    ga++;

    return *ga ? *ga : g;
}

static radixtree_t *eval_nas_member_acl(tac_session * session, tac_user * user)
{
    struct tac_acllist *a = user->nas_member_acl;
    while (a) {
	a = eval_tac_acllist(session, NULL, &a);
	if (a) {
	    if (a->u.rt && radix_lookup(a->u.rt, &session->ctx->nas_address, NULL))
		return a->u.rt;
	    a = a->next;
	}
    }
    return NULL;
}

static int cfg_get(tac_session * session, int (*fun)(tac_user *))
{
    int res = -1, once = 1;
    tac_user *user = session->user;
    tac_user *defaultgroup = NULL;
    char *tag;
    if (!user->nas_member_acl && session->groupname_default) {
	defaultgroup = lookup_user(session->ctx->aaa_realm->grouptable, session->groupname_default);
	if (!defaultgroup)
	    report(session, LOG_INFO, ~0, "host default group %s not found", session->groupname_default);
    }
    do {
	if (once)
	    once = 0;
	else
	    defaultgroup = NULL;
	session->final_match = user->name;
	tag = eval_taglist(session, user);
	report(session, LOG_DEBUG, DEBUG_AUTHOR_FLAG | DEBUG_AUTHEN_FLAG, "%s: checking user/group %s, tag %s", __func__, user->name, tag ? tag : "(NULL)");
    }
    while ((!user->valid_from || (user->valid_from <= io_now.tv_sec))
	   && (!user->valid_until || (user->valid_until > io_now.tv_sec))
	   && (res = fun(user))
	   && (user = defaultgroup ? defaultgroup : member_lookup(session, eval_nas_member_acl(session, user), tag)));

    return res;
}

static struct {
    tac_session *session;
    enum token token;
    int restricted;
} cfg_eval_acl_data;

static int cfg_eval_acl_func(tac_user * u)
{
    if (u && u->acllist) {
	struct tac_acllist *a = eval_tac_acllist(cfg_eval_acl_data.session, NULL, &u->acllist);
	cfg_eval_acl_data.restricted = -1;

	if (a) {
	    cfg_eval_acl_data.token = a->u.token;
	    switch (cfg_eval_acl_data.token) {
	    case S_deny:
	    case S_permit:
		return 0;
	    default:
		;
	    }
	}
    }
    return -1;
}

int cfg_get_access_acl(tac_session * session, enum hint_enum *hint)
{
    cfg_eval_acl_data.session = session;
    cfg_eval_acl_data.token = S_unknown;
    cfg_eval_acl_data.restricted = 0;
    cfg_get(session, cfg_eval_acl_func);
    if (!cfg_eval_acl_data.restricted || cfg_eval_acl_data.token == S_permit)
	return TAC_PLUS_AUTHEN_STATUS_PASS;
    *hint = hint_denied_by_acl;
    return TAC_PLUS_AUTHEN_STATUS_FAIL;
}

static struct {
    struct pwdat *ena;
    int level_implied;
    int level;
} cfg_get_enable_data;

static int cfg_get_enable_func(tac_user * u)
{
    if (u->enable[cfg_get_enable_data.level]) {
	if (!u->enable_implied[cfg_get_enable_data.level]) {
	    cfg_get_enable_data.ena = u->enable[cfg_get_enable_data.level];
	    return 0;
	}
	if (cfg_get_enable_data.level_implied > u->enable_implied[cfg_get_enable_data.level]) {
	    cfg_get_enable_data.ena = u->enable[cfg_get_enable_data.level];
	    cfg_get_enable_data.level_implied = u->enable_implied[cfg_get_enable_data.level];
	}
    }
    return -1;
}

int cfg_get_enable(tac_session * session, struct pwdat **p)
{
    cfg_get_enable_data.ena = NULL;
    if (session->user) {
	cfg_get_enable_data.level = session->priv_lvl;
	cfg_get_enable_data.level_implied = TAC_PLUS_PRIV_LVL_MAX + 1;
	cfg_get(session, cfg_get_enable_func);
    }
    *p = cfg_get_enable_data.ena;
    return *p == NULL;
}

static struct {
    int res;
} cfg_get_hushlogin_data;

static int cfg_get_hushlogin_func(tac_user * u)
{
    if (u->hushlogin != TRISTATE_DUNNO) {
	cfg_get_hushlogin_data.res = u->hushlogin;
	return 0;
    }
    return -1;
}

int cfg_get_hushlogin(tac_session * session)
{
    cfg_get_hushlogin_data.res = TRISTATE_NO;
    if (session->user)
	cfg_get(session, cfg_get_hushlogin_func);
    return cfg_get_hushlogin_data.res;
}

static struct {
    tac_realm *r;
} cfg_get_mavis_realm_data;

static int cfg_get_mavis_realm_func(tac_user * u)
{
    if (u->mavis_realm) {
	cfg_get_mavis_realm_data.r = u->mavis_realm;
	return 0;
    }
    return -1;
}

tac_realm *cfg_get_mavis_realm(tac_session * session)
{
    cfg_get_mavis_realm_data.r = NULL;
    if (session->user)
	cfg_get(session, cfg_get_mavis_realm_func);
    return cfg_get_mavis_realm_data.r;
}

static struct {
    char *msg;
} cfg_get_message_data;

static int cfg_get_message_func(tac_user * u)
{
    if (u->msg) {
	cfg_get_message_data.msg = u->msg;
	return 0;
    }
    return -1;
}

int cfg_get_message(tac_session * session, char **msg)
{
    cfg_get_message_data.msg = NULL;
    if (session->user)
	cfg_get(session, cfg_get_message_func);
    *msg = cfg_get_message_data.msg;
    return *msg == NULL;
}

#define C cfg_get_access_data
static struct {
    tac_session *session;
    int restricted;
} C;

static int cfg_get_access_nac_func(tac_user * u)
{
    if (!u->nac_range && !u->nac_regex)
	return -1;

    if (C.session->nac_address_valid && u->nac_range) {
	C.restricted = -1;
	if (radix_lookup(u->nac_range, &C.session->nac_address, NULL))
	    return 0;
    }

    if (u->nac_regex) {
	struct acl_element **r = &u->nac_regex;
	C.restricted = -1;
	while (*r) {
	    int match;

	    match = match_regex(C.session, (*r)->blob.r, C.session->nac_address_ascii, (*r)->type, (*r)->string);

	    report(C.session, LOG_DEBUG,
		   DEBUG_AUTHEN_FLAG | DEBUG_REGEX_FLAG,
		   "%s@%s: line %u: " "\"%s\" <=> \"%s\" : %smatch",
		   C.session->username,
		   C.session->ctx->nas_address_ascii, (u_int) (*r)->line, C.session->nac_address_ascii, (*r)->string, match ? "" : "no ");
	    if (match)
		return !(*r)->negate;
	    r = &(*r)->next;
	}
    }
    return -1;			/* FAIL */
}

static int cfg_get_access_nas_func(tac_user * u)
{
    if (u->nas_range) {
	C.restricted = -1;
	if (radix_lookup(u->nas_range, &C.session->ctx->nas_address, NULL))
	    return 0;
    }
    return -1;
}

/* return TAC_PLUS_AUTHEN_STATUS_PASS if NAC and NAS address are both ok */
int cfg_get_access(tac_session * session, enum hint_enum *hint)
{
    return ((cfg_get_access_nac(session, hint) != TAC_PLUS_AUTHEN_STATUS_PASS)
	    || (cfg_get_access_nas(session, hint) != TAC_PLUS_AUTHEN_STATUS_PASS)
	    || (cfg_get_access_acl(session, hint) != TAC_PLUS_AUTHEN_STATUS_PASS)) ? TAC_PLUS_AUTHEN_STATUS_FAIL : TAC_PLUS_AUTHEN_STATUS_PASS;
}

/* return 0 if NAS address is ok */
int cfg_get_access_nas(tac_session * session, enum hint_enum *hint)
{
    int res = -1;
    if (session->user) {
	C.session = session;
	C.restricted = 0;
	res = cfg_get(session, cfg_get_access_nas_func) & C.restricted;
	if (res)
	    *hint = hint_bad_nas;
    }
    return res ? TAC_PLUS_AUTHEN_STATUS_FAIL : TAC_PLUS_AUTHEN_STATUS_PASS;
}

/* return 0 if NAC address is ok */
int cfg_get_access_nac(tac_session * session, enum hint_enum *hint)
{
    int res = -1;
    if (session->user) {
	C.session = session;
	C.restricted = 0;
	res = cfg_get(session, cfg_get_access_nac_func) & C.restricted;
	if (res)
	    *hint = hint_bad_nac;
    }
    return res ? TAC_PLUS_AUTHEN_STATUS_FAIL : TAC_PLUS_AUTHEN_STATUS_PASS;
}

#undef C

#define C cfg_get_debug_data
static struct {
    u_int i;
} C;

static int cfg_get_debug_func(tac_user * u)
{
    C.i |= u->debug;
    if (u->debug & DEBUG_NONE_FLAG) {
	C.i = 0;
	return 0;
    }
    return -1;
}

int cfg_get_debug(tac_session * session, u_int * i)
{
    int res = -1;
    C.i = session->debug;
    if (session->user) {
	res = cfg_get(session, cfg_get_debug_func);
	*i = C.i;
    }
    return res;
}

#undef C

#define C cfg_get_client_bug_data
static struct {
    u_int i;
} C;

static int cfg_get_client_bug_func(tac_user * u)
{
    C.i |= u->debug;
    if (u->debug & DEBUG_NONE_FLAG) {
	C.i = 0;
	return 0;
    }
    return -1;
}

int cfg_get_client_bug(tac_session * session, u_int * i)
{
    int res = -1;
    C.i = session->client_bug;
    if (session->user) {
	res = cfg_get(session, cfg_get_client_bug_func);
	*i = C.i;
    }
    return res;
}

#undef C


// 0: no match
static int match_regex(tac_session * session, void *reg, char *txt, enum tac_acl_type tat, char *string)
{
    int res = -1;
    switch (tat) {
    case T_regex_posix:
	res = regexec((regex_t *) reg, txt, 0, NULL, 0);
	report(session, LOG_DEBUG, DEBUG_REGEX_FLAG, "regex: '%s' <=> '%s' = %d", string, txt, res);
	return 0 == res;
    case T_regex_pcre:
#ifdef WITH_PCRE2
	{
	    pcre2_match_data *match_data = pcre2_match_data_create_from_pattern((pcre2_code *) reg, NULL);
	    res = pcre2_match((pcre2_code *) reg, (PCRE2_SPTR) txt, PCRE2_ZERO_TERMINATED, 0, 0, match_data, NULL);
	    pcre2_match_data_free(match_data);
	    report(session, LOG_DEBUG, DEBUG_REGEX_FLAG, "pcre2: '%s' <=> '%s' = %d", string, txt, res);
	}
#endif
	return -1 < res;
    default:
	return 0;
    }
}

static void match_tac_acl(tac_session * session, struct tac_acllist *acl, struct node_svc **node)
{
    if (*node && acl) {
	enum token res = S_unknown;
	struct tac_acllist **tal = &(*node)->acllist;
	while (*tal && res == S_unknown) {
	    res = eval_tac_acl(session, NULL, (*tal)->acl);
	    tal = &(*tal)->next;
	}
	report(session, LOG_DEBUG,
	       DEBUG_ACL_FLAG | DEBUG_AUTHOR_FLAG | DEBUG_REGEX_FLAG,
	       "%s@%s: %s", session->username, session->ctx->nas_address_ascii, (res == S_unknown) ? "no match" : codestring[res]);

	if (res == S_deny)
	    *node = NULL;
    }
}

static void lookup_svc(tac_session * session, tac_user * u,
		       char *svcname, enum token type,
		       char *protocol, char *cmd,
		       struct node_svc **node,
		       struct node_svc **protonode,
		       struct node_cmd **cmdnode, enum token *svc_dflt, enum token *attr_dflt, char **msg_debug, char **msg_permit, char **msg_deny)
{
    struct node_svc *svcp = NULL;
    struct node_svc *protp = NULL;
    struct node_cmd *cmdp = NULL;

    if (*svc_dflt == S_unknown)
	*svc_dflt = u->svc_dflt;

    if (!strchr(svcname, '@')) {
	tac_host **h = NULL;
	for (h = session->ctx->hostchain; *h; h++)
	    if ((*h)->name) {
		char svcbuf[MAX_INPUT_LINE_LEN];
		if (MAX_INPUT_LINE_LEN > snprintf(svcbuf, MAX_INPUT_LINE_LEN, "%s@%s", svcname, (*h)->name)) {
		    lookup_svc(session, u, svcbuf, type, protocol, cmd, node, protonode, cmdnode, svc_dflt, attr_dflt, msg_debug, msg_permit, msg_deny);
		    if (*node)
			return;
		}
	    }
    }

    if (protocol && *protocol) {
	protp = mempool_malloc(session->pool, sizeof(struct node_svc) + strlen(protocol));
	protp->type = keycode(protocol);
	strcpy(protp->name, protocol);
    }
    if (cmd && *cmd) {
	cmdp = mempool_malloc(session->pool, sizeof(struct node_cmd) + strlen(cmd));
	strcpy(cmdp->name, cmd);
    }

    svcp = alloca(sizeof(struct node_svc) + strlen(svcname));
    svcp->type = type;
    strcpy(svcp->name, svcname);
    for (svcp = RB_lookup(u->svcs, svcp); svcp && svcp->acl; svcp = svcp->next) {
	switch (eval_tac_acl(session, NULL, svcp->acl)) {
	case S_permit:
	    if (!svcp->negate) {
		*node = svcp;
		if (attr_dflt && *attr_dflt == S_unknown)
		    *svc_dflt = svcp->attr_dflt;
		goto bye;
	    }
	    break;
	case S_deny:
	    if (svcp->negate) {
		*node = svcp;
		if (attr_dflt && *attr_dflt == S_unknown)
		    *svc_dflt = svcp->attr_dflt;
		goto bye;
	    }
	    break;
	default:
	    ;
	}

	if (svcp->sub) {
	    if (protonode && protp) {
		*protonode = RB_lookup(svcp->sub, protp);
		if (!*protonode && svcp->sub_dflt != S_permit)
		    continue;
	    } else if (cmdnode && cmdp) {
		*cmdnode = RB_lookup(svcp->sub, cmdp);
		if (!*cmdnode && svcp->sub_dflt != S_permit)
		    continue;
	    }
	}
    }

  bye:
    if (svcp && svcp->sub) {
	if (protonode && protp)
	    *protonode = RB_lookup(svcp->sub, protp);
	else if (cmdnode && cmdp)
	    *cmdnode = RB_lookup(svcp->sub, cmdp);
    }

    *node = svcp;

    if (svcp) {
	if (msg_deny && svcp->msg_deny)
	    *msg_deny = svcp->msg_deny;
	if (msg_permit && svcp->msg_permit)
	    *msg_permit = svcp->msg_permit;
	if (msg_debug && svcp->msg_debug)
	    *msg_debug = svcp->msg_debug;
    }
    if (cmdnode && *cmdnode) {
	if (msg_deny && (*cmdnode)->msg_deny)
	    *msg_deny = (*cmdnode)->msg_deny;
	if (msg_permit && (*cmdnode)->msg_permit)
	    *msg_permit = (*cmdnode)->msg_permit;
	if (msg_debug && (*cmdnode)->msg_debug)
	    *msg_debug = (*cmdnode)->msg_debug;
    }
    if (!protocol)
	protocol = "";
    if (!cmd)
	cmd = "";
    report(session, LOG_DEBUG, DEBUG_AUTHOR_FLAG,
	   "%s@%s: %sfound: svcname=%s %s=%s", session->username,
	   session->ctx->nas_address_ascii, *node ? "" : "not ", svcname, protonode ? "protocol" : "cmd", protonode ? protocol : cmd);
}

static int service_is_prohibited(tac_session * session, tac_user * u, char *svcname)
{
    if (u->svc_prohibit && RB_lookup(u->svc_prohibit, svcname)) {
	report(session, LOG_DEBUG, DEBUG_CONFIG_FLAG, "%s: prohibit svcname=%s", __func__, svcname);
	return -1;
    }
    return 0;
}

/*
 * Get attribute-value pairs + permissions for a given service
 */
#define C cfg_get_svc_attrs_data
static struct {
    tac_session *session;
    rb_tree_t *tree_m_a;
    rb_tree_t *tree_m_av;
    rb_tree_t *tree_a_a;
    rb_tree_t *tree_a_av;
    rb_tree_t *tree_o_a;
    rb_tree_t *tree_o_av;
    char *svcname;
    char *protocol;
    enum token type;
    enum token result;
    enum token svc_dflt;
    enum token attr_dflt;
} C;

static enum token tac_script_eval(tac_session *, struct node_svc *, char *, char *, char **);

static int cfg_get_svc_attrs_func(tac_user * u)
{
    struct node_svc *node = NULL;
    struct node_svc *protonode = NULL;

    if (service_is_prohibited(C.session, u, C.svcname))
	return 0;

    lookup_svc(C.session, u, C.svcname, C.type, C.protocol, NULL, &node, &protonode, NULL, &C.svc_dflt, &C.attr_dflt, NULL, NULL, NULL);

    if (!node && C.svc_dflt != S_unknown) {
	if (C.result == S_unknown)
	    C.result = C.svc_dflt;
	return 0;
    }

    if (node) {
	int i;
	char *r = NULL;

	report(C.session, LOG_DEBUG, DEBUG_CONFIG_FLAG, "%s: found svcname=%s proto=%s", __func__, C.svcname ? C.svcname : "", C.protocol ? C.protocol : "");
	match_tac_acl(C.session, node->acllist, &node);
	if (!node)
	    r = "ACL";
	else if (node->script && (S_deny == tac_script_eval(C.session, node, NULL, NULL, NULL)))
	    r = "script";
	if (r) {
	    report(C.session, LOG_DEBUG, DEBUG_CONFIG_FLAG,
		   "%s: svcname=%s proto=%s refused by %s", __func__, C.svcname ? C.svcname : "", C.protocol ? C.protocol : "", r);
	    if (C.result == S_unknown)
		C.result = S_deny;
	    return 0;
	}
	C.result = S_permit;
	if (protonode) {
	    for (i = 0; i < protonode->cnt_m; i++) {
		RB_insert(C.tree_m_a, protonode->attrs_m[i]);
		RB_insert(C.tree_m_av, protonode->attrs_m[i]);
	    }
	    for (i = 0; i < protonode->cnt_a; i++) {
		RB_insert(C.tree_a_a, protonode->attrs_a[i]);
		RB_insert(C.tree_a_av, protonode->attrs_a[i]);
	    }
	    for (i = 0; i < protonode->cnt_o; i++) {
		RB_insert(C.tree_o_a, protonode->attrs_o[i]);
		RB_insert(C.tree_o_av, protonode->attrs_o[i]);
	    }
	}
	for (i = 0; i < node->cnt_m; i++) {
	    if (RB_insert(C.tree_m_a, node->attrs_m[i]))
		RB_insert(C.tree_m_av, node->attrs_m[i]);
	}
	for (i = 0; i < node->cnt_a; i++) {
	    RB_insert(C.tree_a_a, node->attrs_a[i]);
	    RB_insert(C.tree_a_av, node->attrs_a[i]);
	}
	for (i = 0; i < node->cnt_o; i++) {
	    RB_insert(C.tree_o_a, node->attrs_o[i]);
	    RB_insert(C.tree_o_av, node->attrs_o[i]);
	}
	if (node->final)
	    return 0;
    }
    return -1;
}

enum token cfg_get_svc_attrs(tac_session * session, enum token type,
			     char *svcname, char *protocol,
			     rb_tree_t * tree_m_a, rb_tree_t * tree_a_a, rb_tree_t * tree_o_a,
			     rb_tree_t * tree_m_av, rb_tree_t * tree_a_av, rb_tree_t * tree_o_av, enum token *svc_dflt, enum token *attr_dflt)
{
    C.result = S_unknown;
    C.session = session;
    C.type = type;
    C.svcname = svcname;
    C.protocol = protocol;
    C.svc_dflt = S_unknown;
    C.attr_dflt = S_unknown;
    C.tree_m_a = tree_m_a;
    C.tree_a_a = tree_a_a;
    C.tree_o_a = tree_o_a;
    C.tree_m_av = tree_m_av;
    C.tree_a_av = tree_a_av;
    C.tree_o_av = tree_o_av;
    if (session->user)
	cfg_get(session, cfg_get_svc_attrs_func);
    *svc_dflt = C.svc_dflt;
    *attr_dflt = C.attr_dflt;
    return C.result;
}

#undef C

/*
 * Get a pointer to the node representing a set of command regexp matches for
 * a user and command.
 */

#define C get_cmd_node_data
static struct {
    tac_session *session;
    struct node_svc *shell;
    struct node_cmd *node;
    char *cmdname;
    char *args;
    char *format;
    char *msg_debug;
    char *msg_deny;
    char *msg_permit;
    enum token cmd_dflt;
    enum token result;
} C;

static int get_cmd_node_func(tac_user * u)
{
    struct node_svc *shell = NULL;
    struct node_cmd *cmd = NULL;
    enum token svc_dflt = S_unknown;
    tac_session *session = C.session;
    char *cmdname;

    if (service_is_prohibited(session, u, codestring[S_shell]))
	return 0;

    cmdname = alloca(strlen(C.cmdname) + 1);
    strcpy(cmdname, C.cmdname);
    lower(cmdname);

    lookup_svc(session, u, codestring[S_shell], S_shell, NULL, cmdname, &shell, NULL, &cmd, &svc_dflt, NULL, &C.msg_debug, &C.msg_permit, &C.msg_deny);

    if (!shell)
	switch (svc_dflt) {
	case S_permit:
	case S_deny:
	    C.result = svc_dflt;
	    return 0;
	default:
	    return -1;
	}

    if (shell->script) {
	C.result = tac_script_eval(session, shell, C.cmdname, C.args, &C.format);
	switch (C.result) {
	case S_permit:
	case S_deny:
	    return 0;
	default:;
	}
    }

    if (C.cmd_dflt == S_unknown)
	C.cmd_dflt = shell->sub_dflt;

    if (!cmd) {
	if (C.cmd_dflt != S_unknown) {
	    report(session, LOG_DEBUG,
		   DEBUG_AUTHOR_FLAG | DEBUG_REGEX_FLAG,
		   "%s@%s: %s: default is %s", session->username, session->ctx->nas_address_ascii, C.cmdname, codestring[C.cmd_dflt]);
	    C.result = C.cmd_dflt;
	    return 0;
	}
	return -1;
    }

    if (cmd->msg_debug)
	C.msg_debug = cmd->msg_debug;
    if (cmd->msg_deny)
	C.msg_deny = cmd->msg_deny;
    if (cmd->msg_permit)
	C.msg_permit = cmd->msg_permit;

    if (cmd->perm) {
	struct node_perm *node;
	/* command exists and permissions are defined */
	for (node = cmd->perm; node; node = node->next) {
	    int match = match_regex(session, node->regex, C.args, node->regex_type, node->name);

	    report(session, LOG_DEBUG,
		   DEBUG_AUTHOR_FLAG | DEBUG_REGEX_FLAG,
		   "%s@%s: line %u: %s: \"%s\" <=> \"%s\": %s",
		   session->username, session->ctx->nas_address_ascii,
		   (u_int) cmd->line, C.cmdname, C.args, (char *) node->name, match ? codestring[node->type] : "no match");
	    if (match) {
		C.result = node->type;
		return 0;
	    }
	}
    } else {
	/* No permissions are defined, allow the command */
	C.result = S_permit;
	return 0;
    }

    if (shell && shell->final)
	return 0;

    return -1;
}

enum token cfg_get_cmd_node(tac_session * session, char *cmdname, char *args, char **format)
{
    C.result = S_unknown;
    C.session = session;
    C.cmdname = cmdname;
    C.args = args;
    C.format = NULL;
    C.msg_deny = NULL;
    C.msg_debug = NULL;
    C.msg_permit = NULL;
    C.cmd_dflt = S_unknown;
    C.node = NULL;
    if (session->user)
	cfg_get(session, get_cmd_node_func);
    *format = C.format;

    if (!*format) {
	if (C.msg_debug && (session->debug & DEBUG_CMD_FLAG))
	    *format = C.msg_debug;
	else if (C.msg_permit && C.result == S_permit)
	    *format = C.msg_permit;
	else if (C.msg_deny && C.result == S_deny)
	    *format = C.msg_deny;
    }

    if (C.result != S_unknown)
	return C.result;
    return S_deny;
}

#undef C

static struct mavis_cond *tac_script_cond_add(tac_user * u, struct mavis_cond
					      *a, struct mavis_cond
					      *b)
{
    if (a->u.m.n && !(a->u.m.n & 7))
	a = mempool_realloc(u ? u->pool : NULL, a, sizeof(struct mavis_cond) + a->u.m.n * sizeof(struct mavis_cond *));

    a->u.m.e[a->u.m.n] = b;
    a->u.m.n++;
    return a;
}

static struct mavis_cond *tac_script_cond_new(tac_user * u, enum token type)
{
    struct mavis_cond *m = mempool_malloc(u ? u->pool : NULL, sizeof(struct mavis_cond));
    m->type = type;
    return m;
}

static struct mavis_cond *tac_script_cond_parse_r(tac_user * u, struct sym *sym)
{
    struct mavis_cond *m, *p = NULL;
    rb_tree_t *pool = u ? u->pool : NULL;

    switch (sym->code) {
    case S_leftbra:
	tac_sym_get(sym);
	m = tac_script_cond_add(u, tac_script_cond_new(u, S_or), tac_script_cond_parse_r(u, sym));
	if (sym->code == S_and)
	    m->type = S_and;
	while (sym->code == S_and || sym->code == S_or) {
	    tac_sym_get(sym);
	    m = tac_script_cond_add(u, m, tac_script_cond_parse_r(u, sym));
	}
	parse(sym, S_rightbra);
	return m;
    case S_exclmark:
	tac_sym_get(sym);
	m = tac_script_cond_add(u, tac_script_cond_new(u, S_exclmark), tac_script_cond_parse_r(u, sym));
	return m;
    case S_eof:
	parse_error(sym, "EOF unexpected");
    case S_acl:
	m = tac_script_cond_new(u, S_acl);

	tac_sym_get(sym);
	switch (sym->code) {
	case S_exclmark:
	    p = tac_script_cond_add(u, tac_script_cond_new(u, S_exclmark), m);
	case S_equal:
	    break;
	case S_eof:
	    parse_error(sym, "EOF unexpected");
	default:
	    parse_error_expect(sym, S_exclmark, S_equal, S_unknown);
	}
	tac_sym_get(sym);

	m->u.s.rhs = tac_acl_lookup(sym->buf);

	if (!m->u.s.rhs)
	    parse_error(sym, "ACL '%s' not found", sym->buf);
	tac_sym_get(sym);
	return m;
    case S_time:
	m = tac_script_cond_new(u, S_time);

	tac_sym_get(sym);
	switch (sym->code) {
	case S_exclmark:
	    p = tac_script_cond_add(u, tac_script_cond_new(u, S_exclmark), m);
	case S_equal:
	    break;
	case S_eof:
	    parse_error(sym, "EOF unexpected");
	default:
	    parse_error_expect(sym, S_exclmark, S_equal, S_unknown);
	}
	tac_sym_get(sym);

	m->u.s.rhs = find_timespec(timespectable, sym->buf);
	if (!m->u.s.rhs)
	    parse_error(sym, "timespec '%s' not found", sym->buf);
	tac_sym_get(sym);
	return m;
    case S_cmd:
    case S_command:
    case S_context:
    case S_nac:
    case S_nas:
    case S_nasname:
    case S_nacname:
    case S_nasrealm:
    case S_nacrealm:
    case S_aaarealm:
    case S_port:
    case S_user:
    case S_password:
	m = tac_script_cond_new(u, S_equal);
	m->u.s.token = sym->code;

	tac_sym_get(sym);
	switch (sym->code) {
	case S_exclmark:
	    p = tac_script_cond_add(u, tac_script_cond_new(u, S_exclmark), m);
	case S_equal:
	    break;
	case S_eof:
	    parse_error(sym, "EOF unexpected");
	default:
	    parse_error_expect(sym, S_exclmark, S_equal, S_unknown);
	}
	tac_sym_get(sym);
	switch (sym->code) {
	case S_equal:
	    m->type = S_equal;
	    if (m->u.s.token == S_nac || m->u.s.token == S_nas) {
		tac_host h, *hp;
		tac_sym_get(sym);
		h.name = sym->buf;
		hp = RB_lookup(hosttable, (void *) &h);
		if (hp) {
		    m->type = S_host;
		    m->u.s.rhs = hp;
		} else {
		    struct in6_cidr *c = mempool_malloc(pool, sizeof(struct in6_cidr));
		    m->u.s.rhs = c;
		    if (v6_ptoh(&c->addr, &c->mask, sym->buf))
			parse_error(sym, "Expected a hostname or an IP " "address/network in CIDR notation, " "but got '%s'.", sym->buf);
		    m->type = S_address;
		}
		tac_sym_get(sym);
		return p ? p : m;
	    }
	    break;
	case S_tilde:
	    m->type = S_regex;
	    sym->flag_parse_pcre = 1;
	    break;
	case S_eof:
	    parse_error(sym, "EOF unexpected");
	default:
	    parse_error_expect(sym, S_equal, S_tilde, S_unknown);
	}

	tac_sym_get(sym);
	if (m->type == S_equal) {
	    m->u.s.rhs = mempool_strdup(pool, sym->buf);

	    tac_sym_get(sym);
	    return p ? p : m;
	} else {
	    int errcode = 0;
	    if (sym->code == S_slash) {
#ifdef WITH_PCRE2
		PCRE2_SIZE erroffset;
		m->type = S_slash;
		m->u.s.rhs =
		    pcre2_compile((PCRE2_SPTR8) sym->buf, PCRE2_ZERO_TERMINATED, PCRE2_MULTILINE | common_data.regex_pcre_flags, &errcode, &erroffset, NULL);
		if (u && u->pool_pcre) {
		    RB_insert(u->pool_pcre, m->u.s.rhs);
		    m->u.s.rhs_txt = mempool_strdup(u->pool, sym->buf);
		}

		if (!m->u.s.rhs) {
		    PCRE2_UCHAR buffer[256];
		    pcre2_get_error_message(errcode, buffer, sizeof(buffer));
		    parse_error(sym, "In PCRE2 expression /%s/ at offset %d: %s", sym->buf, erroffset, buffer);
		}
		sym->flag_parse_pcre = 0;
		tac_sym_get(sym);
		return p ? p : m;
#else
		parse_error(sym, "You're using PCRE2 syntax, but this binary wasn't compiled with PCRE2 support.");
#endif
	    }
	    m->u.s.rhs = mempool_malloc(pool, sizeof(regex_t));
	    errcode = regcomp((regex_t *) m->u.s.rhs, sym->buf, REG_EXTENDED | REG_NOSUB | REG_NEWLINE | common_data.regex_posix_flags);
	    if (errcode) {
		char e[160];
		regerror(errcode, (regex_t *) m->u.s.rhs, e, sizeof(e));
		parse_error(sym, "In regular expression '%s': %s", sym->buf, e);
	    } else if (u && u->pool_regex)
		RB_insert(u->pool_regex, m->u.s.rhs);
	    tac_sym_get(sym);
	    return p ? p : m;
	}
    default:
	parse_error_expect(sym, S_leftbra, S_acl, S_exclmark, S_command,
			   S_context, S_time, S_cmd, S_nac, S_nas, S_nacname, S_nasname, S_nasrealm, S_nacrealm, S_port, S_user, S_password, S_unknown);
    }
    return NULL;
}

static void tac_script_cond_optimize(tac_user * u, struct mavis_cond **m)
{
    struct mavis_cond *p;
    rb_tree_t *pool = u ? u->pool : NULL;
    int i;
    while (*m && ((*m)->type == S_or || (*m)->type == S_and) && (*m)->u.m.n == 1) {
	p = *m;
	*m = (*m)->u.m.e[0];
	mempool_free(pool, &p);
    }
    if (*m)
	for (i = 0; i < (*m)->u.m.n; i++)
	    if ((*m)->type == S_or || (*m)->type == S_and || (*m)->type == S_exclmark)
		tac_script_cond_optimize(u, &(*m)->u.m.e[i]);
}

static struct mavis_cond *tac_script_cond_parse(tac_user * u, struct sym *sym)
{
    struct sym *cond_sym = NULL;
    if (sym_normalize_cond_start(sym, &cond_sym)) {
	struct mavis_cond *m = tac_script_cond_parse_r(u, cond_sym);
	sym_normalize_cond_end(&cond_sym);
	tac_script_cond_optimize(u, &m);
	return m;
    }
    return tac_script_cond_parse_r(u, sym);
}

static int tac_script_cond_eval(tac_session * session, char *cmd, struct mavis_cond *m)
{
    int i;
    char *v = NULL;
    if (!m)
	return 0;
    switch (m->type) {
    case S_exclmark:
	return !tac_script_cond_eval(session, cmd, m->u.m.e[0]);
    case S_and:
	for (i = 0; i < m->u.m.n; i++)
	    if (!tac_script_cond_eval(session, cmd, m->u.m.e[i]))
		return 0;
	return -1;
    case S_or:
	for (i = 0; i < m->u.m.n; i++)
	    if (tac_script_cond_eval(session, cmd, m->u.m.e[i]))
		return -1;
	return 0;
    case S_equal:
	switch (m->u.s.token) {
	case S_context:
	    v = tac_script_get_exec_context(session, session->username, session->nas_port);
	    break;
	case S_cmd:
	case S_command:
	    v = cmd;
	    break;
	default:;
	}
	if (!v)
	    return 0;
	return !strcmp(v, m->u.s.rhs);

    case S_address:
	switch (m->u.s.token) {
	case S_nac:
	    if (session->nac_address_valid)
		return v6_contains(&((struct in6_cidr *) (m->u.s.rhs))->addr, ((struct in6_cidr *) (m->u.s.rhs))->mask, &session->nac_address);
	    return 0;
	case S_nas:
	    return v6_contains(&((struct in6_cidr *) (m->u.s.rhs))->addr, ((struct in6_cidr *) (m->u.s.rhs))->mask, &session->ctx->nas_address);
	default:
	    return 0;
	}

    case S_host:
	switch (m->u.s.token) {
	case S_nas:
	    {
		tac_host **h;
		for (h = (session->ctx->hostchain); *h; h++)
		    if ((*h)->name && (*h == (tac_host *) (m->u.s.rhs)))
			return -1;
		return 0;
	    }
	case S_nac:
	    if (session->nac_address_valid)
		return radix_lookup(((tac_host *) (m->u.s.rhs))->addrtree, &session->nac_address, NULL) ? -1 : 0;
	default:
	    return 0;
	}
    case S_time:
	return eval_timespec((struct mavis_timespec *) m->u.s.rhs, NULL);
    case S_acl:
	return S_permit == eval_tac_acl(session, cmd, (struct tac_acl *) m->u.s.rhs);
    case S_regex:
    case S_slash:
	switch (m->u.s.token) {
	case S_context:
	    v = tac_script_get_exec_context(session, session->username, session->nas_port);
	    break;
	case S_cmd:
	case S_command:
	    v = cmd;
	    break;
	case S_nac:
	    v = session->nac_address_ascii;
	    break;
	case S_nas:
	    v = session->ctx->nas_address_ascii;
	    break;
	case S_nacname:
	    if (session->nac_dns_name && *session->nac_dns_name)
		v = session->nac_dns_name;
	    break;
	case S_nasname:
	    if (session->ctx->nas_dns_name && *session->ctx->nas_dns_name)
		v = session->ctx->nas_dns_name;
	    break;
	case S_nacrealm:
	    v = session->ctx->nac_realm->name;
	    break;
	case S_nasrealm:
	    v = session->ctx->realm->name;
	    break;
	case S_aaarealm:
	    v = session->ctx->aaa_realm->name;
	    break;
	case S_port:
	    v = session->nas_port;
	    break;
	case S_user:
	    v = session->username;
	    break;
	case S_password:
	    v = session->password_new ? session->password_new : session->password;
	    break;
	default:;
	}
	if (!v)
	    return 0;
	if (m->type == S_slash) {
	    int res = -1;
#ifdef WITH_PCRE2
	    pcre2_match_data *match_data = pcre2_match_data_create_from_pattern((pcre2_code *) m->u.s.rhs, NULL);
	    res = pcre2_match((pcre2_code *) m->u.s.rhs, (PCRE2_SPTR) v, PCRE2_ZERO_TERMINATED, 0, 0, match_data, NULL);
	    pcre2_match_data_free(match_data);
	    report(session, LOG_DEBUG, DEBUG_REGEX_FLAG, "pcre2: '%s' <=> '%s' = %d", m->u.s.rhs_txt, v, res);
#endif
	    return -1 < res;
	}
	return !regexec((regex_t *) m->u.s.rhs, v, 0, NULL, 0);
    default:;
    }
    return 0;
}

static enum token tac_script_eval_r(tac_session * session, char *cmd, struct mavis_action *m, char **format)
{
    enum token r;

    if (!m)
	return S_unknown;
    switch (m->code) {
    case S_return:
    case S_permit:
    case S_deny:
	return m->code;
    case S_context:
	tac_script_set_exec_context(session, session->username, session->nas_port, m->b.v);
	break;
    case S_message:
	if (format)
	    *format = m->b.v;
	break;
    case S_if:
	if (tac_script_cond_eval(session, cmd, m->a.c)) {
	    r = tac_script_eval_r(session, cmd, m->b.a, format);
	    if (r != S_unknown)
		return r;
	} else if (m->c.a) {
	    r = tac_script_eval_r(session, cmd, m->c.a, format);
	    if (r != S_unknown)
		return r;
	}
	break;
    default:
	return S_unknown;
    }
    return m->n ? tac_script_eval_r(session, cmd, m->n, format) : S_unknown;
}

static struct mavis_action *tac_script_parse_r(tac_user * u, struct sym *sym, int section)
{
    struct mavis_action *m = NULL;
    rb_tree_t *pool = u ? u->pool : NULL;

    switch (sym->code) {
    case S_eof:
	parse_error(sym, "EOF unexpected");
    case S_closebra:
	return NULL;
    case S_openbra:
	tac_sym_get(sym);
	m = tac_script_parse_r(u, sym, 1);
	parse(sym, S_closebra);
	break;
    case S_return:
    case S_permit:
    case S_deny:
	m = mavis_action_new(sym);
	break;
    case S_context:
    case S_message:
	m = mavis_action_new(sym);
	parse(sym, S_equal);
	m->b.v = mempool_strdup(pool, sym->buf);
	tac_sym_get(sym);
	break;
    case S_if:
	m = mavis_action_new(sym);
	m->a.c = tac_script_cond_parse(u, sym);
	m->b.a = tac_script_parse_r(u, sym, 0);
	if (sym->code == S_else) {
	    tac_sym_get(sym);
	    m->c.a = tac_script_parse_r(u, sym, 0);
	}
	break;
    default:
	parse_error_expect(sym, S_openbra, S_closebra, S_return, S_permit, S_deny, S_context, S_message, S_if, S_unknown);
    }
    if (section && sym->code != S_closebra && sym->code != S_eof)
	m->n = tac_script_parse_r(u, sym, section);
    return m;
}

static void tac_script_parse(tac_user * u, struct node_svc *shell, struct sym *sym)
{
    struct mavis_action **p = &shell->script;

    while (*p)
	p = &(*p)->n;

    tac_sym_get(sym);
    parse(sym, S_equal);
    parse(sym, S_openbra);
    *p = tac_script_parse_r(u, sym, 1);
    parse(sym, S_closebra);
}

static enum token tac_script_eval(tac_session * session, struct node_svc *svc, char *cmd, char *args, char **format)
{
    char *a;
    size_t len;

    if (!svc->script)
	return S_unknown;

    if (!cmd)
	cmd = "";
    if (!args)
	args = "";

    len = strlen(cmd) + strlen(args) + 2;

    a = alloca(len);
    if (len > 2) {
	strcpy(a, cmd);
	strcat(a, " ");
	strcat(a, args);
    } else
	a = "";

    return tac_script_eval_r(session, a, svc->script, format);
}

#ifdef WITH_PCRE2
void tac_rewrite_user(tac_session * session)
{
    if (!session->username_rewritten && session->ctx->rewrite_user) {
	int rc = -1;
	tac_rewrite_expr *e = session->ctx->rewrite_user->expr;
	for (; e && rc < 1; e = e->next) {
	    PCRE2_SPTR replacement = e->replacement;
	    PCRE2_UCHAR outbuf[1024];
	    PCRE2_SIZE outlen = sizeof(outbuf);
	    pcre2_match_data *match_data = pcre2_match_data_create_from_pattern(e->code, NULL);
	    rc = pcre2_substitute(e->code, (PCRE2_SPTR8) session->username, PCRE2_ZERO_TERMINATED, 0, PCRE2_SUBSTITUTE_EXTENDED, match_data, NULL,
				  replacement, PCRE2_ZERO_TERMINATED, outbuf, &outlen);
	    pcre2_match_data_free(match_data);
	    report(session, LOG_DEBUG, DEBUG_REGEX_FLAG, "pcre2: '%s' <=> '%s' = %d", e->name, session->username, rc);
	    if (rc > 0) {
		session->username = mempool_strndup(session->pool, outbuf, outlen);
		session->username_rewritten = 1;
		report(session, LOG_DEBUG, DEBUG_REGEX_FLAG, "pcre2: setting username to '%s'", session->username);
	    }
	}
    }
}
#endif

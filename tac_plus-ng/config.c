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

#ifdef WITH_PCRE
#include <pcre.h>
#endif
#ifdef WITH_PCRE2
#include <pcre2.h>
#endif

#include <regex.h>

static const char rcsid[] __attribute__((used)) = "$Id$";

struct tac_acllist {
    struct tac_acllist *next;
    struct tac_acl *acl;
    union {
	struct upwdat *passwdp;
    } u;
};

struct in6_cidr {
    struct in6_addr addr;
    int mask;
};

struct tac_script_action {
    enum token code;
    union {
	struct tac_script_cond *c;	//if (c)
	int a;			// set a = v / unset a
    } a;
    union {
	struct tac_script_action *a;	//then a
	char *v;
    } b;
    union {
	struct tac_script_action *a;	//else a
    } c;
    struct tac_script_action *n;
};

static void parse_host(struct sym *, tac_realm *, tac_host *);
static void parse_net(struct sym *, tac_realm *, tac_net *);
static void parse_user(struct sym *, tac_realm *);
static void parse_group(struct sym *, tac_realm *, tac_group *);
static void parse_ruleset(struct sym *, tac_realm *);
static void parse_profile(struct sym *, tac_realm *);
static void parse_profile_attr(struct sym *, tac_profile *, tac_realm *);
static void parse_user_attr(struct sym *, tac_user *);
static void parse_tac_acl(struct sym *, tac_realm *);
static void parse_rewrite(struct sym *, tac_realm *);
static void parse_member(struct sym *, tac_groups **, memlist_t *, tac_realm *);

static tac_group *lookup_group(char *, tac_realm *);	/* get id from tree */
static tac_group *tac_group_new(struct sym *, char *, tac_realm *);	/* add name to tree, return id (globally unique) */
static int tac_group_add(tac_group *, tac_groups *, memlist_t *);	/* add id to groups struct */
static int tac_group_check(tac_group *, tac_groups *);	/* check for id in groups struct. The recursive function will temporaly set visited to 1 for loop avoidance */

int compare_user(const void *a, const void *b)
{
    return strcmp(((tac_user *) a)->name, ((tac_user *) b)->name);
}

static int compare_profile(const void *a, const void *b)
{
    return strcmp(((tac_profile *) a)->name, ((tac_profile *) b)->name);
}

static int compare_rewrite(const void *a, const void *b)
{
    return strcmp(((tac_rewrite *) a)->name, ((tac_rewrite *) b)->name);
}

static int compare_realm(const void *a, const void *b)
{
    return strcmp(((tac_realm *) a)->name, ((tac_realm *) b)->name);
}

static struct tac_acl *tac_acl_lookup(char *, tac_realm *);

struct tac_groups {
    u_int count;
    u_int allocated;		/* will be incfremented on demand */
    tac_group **groups;		/* array will be reallocated on demand */
    tac_group ***groupsp;	/* array will be reallocated on demand */
};

struct tac_group;
typedef struct tac_group tac_group;

struct tac_group {
    char *name;			/* groupname */
    tac_group *parent;
    tac_groups *groups;
    u_int line;
    u_int visited:1;
};

static int compare_groups_by_name(const void *a, const void *b)
{
    return strcmp(((tac_group *) a)->name, ((tac_group *) b)->name);
}

static int compare_acl(const void *a, const void *b)
{
    return strcmp(((struct tac_acl *) a)->name, ((struct tac_acl *) b)->name);
}

static int compare_host(const void *a, const void *b)
{
    return strcmp(((tac_host *) a)->name, ((tac_host *) b)->name);
}

static int compare_net(const void *a, const void *b)
{
    return strcmp(((tac_net *) a)->name, ((tac_net *) b)->name);
}

void complete_realm(tac_realm * r)
{
    if (r->parent && !r->complete) {
	tac_realm *rp = r->parent;
	r->complete = 1;

	if (r->chalresp == TRISTATE_DUNNO)
	    r->chalresp = rp->chalresp;
	if (r->chalresp_noecho == TRISTATE_DUNNO)
	    r->chalresp_noecho = rp->chalresp_noecho;
	if (r->chpass == TRISTATE_DUNNO)
	    r->chpass = rp->chpass;
	if (r->mavis_userdb == TRISTATE_DUNNO)
	    r->mavis_userdb = rp->mavis_userdb;
	if (r->mavis_noauthcache == TRISTATE_DUNNO)
	    r->mavis_noauthcache = rp->mavis_noauthcache;
	if (r->mavis_pap == TRISTATE_DUNNO)
	    r->mavis_pap = rp->mavis_pap;
	if (r->mavis_login == TRISTATE_DUNNO)
	    r->mavis_login = rp->mavis_login;
	if (r->mavis_pap_prefetch == TRISTATE_DUNNO)
	    r->mavis_pap_prefetch = rp->mavis_pap_prefetch;
	if (r->mavis_login_prefetch == TRISTATE_DUNNO)
	    r->mavis_login_prefetch = rp->mavis_login_prefetch;
	if (r->caching_period < 0)
	    r->caching_period = rp->caching_period;
	if (r->warning_period < 0)
	    r->warning_period = rp->warning_period;
	if (r->backend_failure_period < 0)
	    r->backend_failure_period = rp->backend_failure_period;
	if (!r->mavis_user_acl)
	    r->mavis_user_acl = rp->mavis_user_acl;
	if (!r->enable_user_acl)
	    r->enable_user_acl = rp->enable_user_acl;
	if (!r->password_acl)
	    r->password_acl = rp->password_acl;
#ifdef WITH_TLS
	if (r->tls_accept_expired == TRISTATE_DUNNO)
	    r->tls_accept_expired = rp->tls_accept_expired;
	if (r->tls_cfg && r->tls_cert) {
	    uint8_t *p;
	    size_t p_len;

	    tls_config_verify_client(r->tls_cfg);
	    if (r->tls_cafile && tls_config_set_ca_file(r->tls_cfg, r->tls_cafile)) {
		const char *terr = tls_config_error(r->tls_cfg);
		report(NULL, LOG_ERR, ~0, "realm %s: tls_config_set_ca_path(\"%s\") failed%s%s", r->name, r->tls_cafile, terr ? ": " : "", terr ? terr : "");
		exit(EX_CONFIG);
	    }
	    if (tls_config_set_protocols(r->tls_cfg, TLS_PROTOCOL_TLSv1_3)) {
		const char *terr = tls_config_error(r->tls_cfg);
		report(NULL, LOG_ERR, ~0, "realm %s: tls_config_set_protocols failed%s%s", r->name, terr ? ": " : "", terr ? terr : "");
		exit(EX_CONFIG);
	    }
	    if (tls_config_set_ciphers(r->tls_cfg, r->tls_ciphers)) {
		const char *terr = tls_config_error(r->tls_cfg);
		report(NULL, LOG_ERR, ~0, "realm %s: tls_config_set_ciphers(\"%s\") failed%s%s", r->name, r->tls_ciphers, terr ? ": " : "", terr ? terr : "");
		exit(EX_CONFIG);
	    }
	    if (!(p = tls_load_file(r->tls_cert, &p_len, NULL))) {
		report(NULL, LOG_ERR, ~0, "realm %s: tls_load_file(%s) failed: %s", r->name, r->tls_cert, strerror(errno));
		exit(EX_CONFIG);
	    }
	    if (tls_config_set_cert_mem(r->tls_cfg, p, p_len)) {
		const char *terr = tls_config_error(r->tls_cfg);
		report(NULL, LOG_ERR, ~0, "realm %s: tls_config_set_cert_mem failed%s%s", r->name, terr ? ": " : "", terr ? terr : "");
		exit(EX_CONFIG);
	    }
	    if (!r->tls_key) {
		report(NULL, LOG_ERR, ~0, "realm %s: No key defined for cert %s", r->name, r->tls_cert);
		exit(EX_CONFIG);
	    }
	    if (!(p = tls_load_file(r->tls_key, &p_len, r->tls_pass))) {
		report(NULL, LOG_ERR, ~0, "realm %s: tls_load_file(%s) failed: %s", r->name, r->tls_key, strerror(errno));
		exit(EX_CONFIG);
	    }
	    if (tls_config_set_key_mem(r->tls_cfg, p, p_len)) {
		report(NULL, LOG_ERR, ~0, "realm %s: tls_config_set_cert_mem failed", r->name);
		exit(EX_CONFIG);
	    }
	    if (!(r->tls_ctx = tls_server())) {
		report(NULL, LOG_ERR, ~0, "realm %s: tls_server() returned NULL", r->name);
		exit(EX_CONFIG);
	    }
	    if (tls_configure(r->tls_ctx, r->tls_cfg)) {
		const char *terr = tls_config_error(r->tls_cfg);
		report(NULL, LOG_ERR, ~0, "realm %s: tls_configure failed%s%s", r->name, terr ? ": " : "", terr ? terr : "");
		exit(EX_CONFIG);
	    }
	} else
	    r->tls_cfg = rp->tls_cfg;
#endif
#ifdef WITH_PCRE2
	if (!r->password_minimum_requirement)
	    r->password_minimum_requirement = rp->password_minimum_requirement;
#endif
	r->debug |= rp->debug;

	if (r->mavis_userdb != TRISTATE_YES)
	    r->mavis_pap_prefetch = TRISTATE_NO;
	if (r->caching_period < 11)
	    r->caching_period = 0;

    }
    if (r->realms) {
	rb_node_t *rbn;
	for (rbn = RB_first(r->realms); rbn; rbn = RB_next(rbn))
	    complete_realm(RB_payload(rbn, tac_realm *));
    }
}

tac_realm *lookup_realm(char *name, tac_realm * r)
{
    if (!strcmp(name, r->name))
	return r;

    if (r->realms) {
	tac_realm *res;
	rb_node_t *rbn;
	for (rbn = RB_first(r->realms); rbn; rbn = RB_next(rbn))
	    if ((res = lookup_realm(name, RB_payload(rbn, tac_realm *))))
		return res;
    }
    return NULL;
}

radixtree_t *lookup_hosttree(tac_realm * r)
{
    while (r) {
	if (r->hosttree)
	    return r->hosttree;
	r = r->parent;
    }
    return NULL;
}

static void parse_inline(char *format, char *file, int line)
{
    struct sym sym;
    memset(&sym, 0, sizeof(sym));
    sym.filename = file;
    sym.line = line;
    sym.in = sym.tin = format;
    sym.len = sym.tlen = strlen(sym.in);
    sym_init(&sym);
}

static tac_realm *new_realm(char *name, tac_realm * parent)
{
    tac_realm *r;

    r = calloc(1, sizeof(tac_realm));
    if (parent) {
	r->parent = parent;
	r->caching_period = -1;
	r->warning_period = -1;
	r->backend_failure_period = -1;
    } else {
	config.default_realm = r;
	r->complete = 1;
	r->caching_period = 120;
	r->warning_period = 86400 * 14;
	r->backend_failure_period = 60;
	r->debug = common_data.debug;

	parse_inline("acl __internal__username_acl__ { if (user =~ \"[]<>/()|=[*\\\"':$]+\") deny permit }\n", __FILE__, __LINE__);
	r->mavis_user_acl = tac_acl_lookup("__internal__username_acl__", r);

	parse_inline("acl __internal__enable_user__ { if (user =~ \"^$enab..$$\") permit deny }", __FILE__, __LINE__);
	r->enable_user_acl = tac_acl_lookup("__internal__enable_user__", r);

    }
    r->name = strdup(name);
    r->chalresp = TRISTATE_DUNNO;
    r->chpass = TRISTATE_DUNNO;
    r->mavis_userdb = TRISTATE_DUNNO;
    r->mavis_noauthcache = TRISTATE_DUNNO;
    r->mavis_pap = TRISTATE_DUNNO;
    r->mavis_login = TRISTATE_DUNNO;
    r->mavis_pap_prefetch = TRISTATE_DUNNO;
    r->mavis_login_prefetch = TRISTATE_DUNNO;
    r->default_host = calloc(1, sizeof(tac_host));
    r->default_host->name = "default";
    r->default_host->authen_max_attempts = -1;
#ifdef WITH_TLS
    r->tls_ciphers = "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384";
#endif

    return r;
}

void init_mcx(tac_realm * r)
{
    rb_node_t *rbn;
    if (r->mcx)
	mavis_init(r->mcx, MAVIS_API_VERSION);
    if (r->realms)
	for (rbn = RB_first(r->realms); rbn; rbn = RB_next(rbn))
	    init_mcx(RB_payload(rbn, tac_realm *));
}

void drop_mcx(tac_realm * r)
{
    rb_node_t *rbn;
    if (r->mcx)
	mavis_drop(r->mcx);
    if (r->realms)
	for (rbn = RB_first(r->realms); rbn; rbn = RB_next(rbn))
	    drop_mcx(RB_payload(rbn, tac_realm *));
}

void expire_dynamic_users(tac_realm * r)
{
    rb_node_t *rbn;
    if (r->usertable) {
	rb_node_t *rbnext;
	for (rbn = RB_first(r->usertable); rbn; rbn = rbnext) {
	    time_t v = RB_payload(rbn, tac_user *)->dynamic;
	    rbnext = RB_next(rbn);

	    if (v && v < io_now.tv_sec)
		RB_delete(r->usertable, rbn);
	}
    }
    if (r->realms)
	for (rbn = RB_first(r->realms); rbn; rbn = RB_next(rbn))
	    expire_dynamic_users(RB_payload(rbn, tac_realm *));
}

tac_user *lookup_user(char *username, tac_realm * r)
{
    tac_user user;
    user.name = username;
    while (r) {
	if (r->usertable) {
	    rb_node_t *rbn = RB_search(r->usertable, &user);
	    if (rbn) {
		tac_user *res = RB_payload(rbn, tac_user *);
		if (res->dynamic && (res->dynamic < io_now.tv_sec)) {
		    RB_delete(r->usertable, rbn);
		    return NULL;
		}
		return res;
	    }
	    return NULL;
	}
	r = r->parent;
    }
    return NULL;
}

static tac_profile *lookup_profile(char *name, tac_realm * r)
{
    tac_profile profile;
    profile.name = name;
    while (r) {
	if (r->profiletable) {
	    tac_profile *res;
	    if ((res = RB_lookup(r->profiletable, &profile)))
		return res;
	}
	r = r->parent;
    }
    return NULL;
}

static tac_rewrite *lookup_rewrite(char *name, tac_realm * r)
{
    tac_rewrite rewrite;
    rewrite.name = name;
    while (r) {
	if (r->rewrite) {
	    tac_rewrite *res;
	    if ((res = RB_lookup(r->rewrite, &rewrite)))
		return res;
	}
	r = r->parent;
    }
    return NULL;
}

tac_host *lookup_host(char *name, tac_realm * r)
{
    tac_host host;
    host.name = name;
    while (r) {
	if (r->hosttable) {
	    tac_host *res;
	    if ((res = RB_lookup(r->hosttable, &host)))
		return res;
	}
	r = r->parent;
    }
    return NULL;
}

static tac_net *lookup_net(char *name, tac_realm * r)
{
    tac_net net;
    net.name = name;
    while (r) {
	if (r->nettable) {
	    tac_net *res;
	    if ((res = RB_lookup(r->nettable, &net)))
		return res;
	}
	r = r->parent;
    }
    return NULL;
}

static struct mavis_timespec *lookup_timespec(char *name, tac_realm * r)
{
    while (r) {
	if (r->timespectable) {
	    struct mavis_timespec *res;
	    if ((res = find_timespec(r->timespectable, name)))
		return res;
	}
	r = r->parent;
    }
    return NULL;
}

static struct sym *globerror_sym = NULL;

static int globerror(const char *epath, int eerrno)
{
    report_cfg_error(LOG_ERR, ~0, "%s:%u: glob(%s): %s", globerror_sym->filename, globerror_sym->line, epath, strerror(eerrno));
    return 0;
}

static time_t parse_date(struct sym *sym, time_t offset);

static void parse_key(struct sym *sym, struct tac_key **tk)
{
    int keylen;
    time_t warn = 0;

    sym_get(sym);
    if (sym->code == S_warn) {
	sym_get(sym);
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
    (*tk)->line = sym->line;
    strncpy((*tk)->key, sym->buf, keylen);

    sym_get(sym);
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

static void dns_add_a(rb_tree_t ** t, struct in6_addr *a, char *name)
{
    struct dns_forward_mapping *ds, *dn = calloc(1, sizeof(struct dns_forward_mapping));
    struct dns_forward_mapping **dsp = &ds;

    if (!*t)
	*t = RB_tree_new(compare_dns_tree_a, NULL);

    dn->name = name;
    ds = (struct dns_forward_mapping *) RB_lookup(*t, dn);
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
    RB_insert(*t, dn);
}

static struct dns_forward_mapping *dns_lookup_a(tac_realm * r, char *name, int recurse)
{
    while (r) {
	if (r->dns_tree_a) {
	    struct dns_forward_mapping dn, *res;
	    dn.name = name;
	    res = (struct dns_forward_mapping *) RB_lookup(r->dns_tree_a, &dn);
	    if (res)
		return res;
	}
	if (!recurse)
	    return NULL;
	r = r->parent;
    }
    return NULL;
}

static void parse_etc_hosts(char *url, tac_realm * r)
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
	    sym_get(&sym);
	    if (sym.line != line)
		continue;
	    radix_add(dns_tree_ptr_static, &a, cm, strdup(sym.buf));
	}

	do {
	    dns_add_a(&r->dns_tree_a, &a, sym.buf);
	    sym_get(&sym);
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

void parse_decls_real(struct sym *, tac_realm *);

static int loopcheck_group(tac_group * g)
{
    int res = 0;
    if (g->visited)
	return -1;
    g->visited = 1;
    if (g->parent)
	res = loopcheck_group(g->parent);
    g->visited = 0;
    return res;
}

static int loopcheck_realm(tac_realm * r)
{
    int res = 0;
    if (r->visited)
	return -1;
    r->visited = 1;
    if (r->parent)
	res = loopcheck_realm(r->parent);
    r->visited = 0;
    return res;
}

static int loopcheck_net(tac_net * n)
{
    int res = 0;
    if (n->visited)
	return -1;
    n->visited = 1;
    if (n->parent)
	res = loopcheck_net(n->parent);
    n->visited = 0;
    return res;
}

static int loopcheck_host(tac_host * h)
{
    int res = 0;
    if (h->visited)
	return -1;
    h->visited = 1;
    if (h->parent)
	res = loopcheck_host(h->parent);
    h->visited = 0;
    return res;
}

tac_realm *parse_realm(struct sym *sym, char *name, tac_realm * parent)
{
    tac_realm *nrealm;

    nrealm = new_realm(sym->buf, parent);
    nrealm->line = sym->line;
    nrealm->name = name;
    nrealm->name_len = strlen(name);

#ifdef WITH_TLS
    if (!(nrealm->tls_cfg = tls_config_new())) {
	report(NULL, LOG_ERR, ~0, "realm %s: tls_config_new() failed", name);
    }
#endif

    parse_decls_real(sym, nrealm);

    /* might need to fix that: */
    if (!nrealm->parent)
	nrealm->parent = parent;
    if (nrealm->parent) {
	nrealm->default_host->tcp_timeout = nrealm->parent->default_host->tcp_timeout;
	nrealm->default_host->session_timeout = nrealm->parent->default_host->session_timeout;
	nrealm->default_host->context_timeout = nrealm->parent->default_host->context_timeout;
    } else {
	nrealm->default_host->session_timeout = 240;
	nrealm->default_host->tcp_timeout = 600;
	nrealm->default_host->context_timeout = 3600;
	nrealm->default_host->authen_max_attempts = 1;
    }
    return nrealm;
}

static void parse_host_attr(struct sym *, tac_realm *, tac_host *);

void parse_decls_real(struct sym *sym, tac_realm * r)
{
    /* Top level of parser */
    while (sym->code != S_closebra)
	switch (sym->code) {
	case S_closebra:
	case S_eof:
	    parse_error(sym, "EOF unexpected");
	case S_password:
	    sym_get(sym);
	    switch (sym->code) {
	    case S_acl:
		sym_get(sym);
		parse(sym, S_equal);
		r->password_acl = tac_acl_lookup(sym->buf, r);
		if (!r->password_acl)
		    parse_error(sym, "ACL '%s' not found)", sym->buf);
		sym_get(sym);
		continue;
	    case S_maxattempts:
		sym_get(sym);
		parse(sym, S_equal);
		r->default_host->authen_max_attempts = parse_int(sym);
		return;
	    default:
		parse_error_expect(sym, S_acl, S_maxattempts, S_unknown);
	    }
	case S_pap:
	    sym_get(sym);
	    switch (sym->code) {
	    case S_backend:
		sym_get(sym);
		parse(sym, S_equal);
		parse(sym, S_mavis);
		if (sym->code == S_prefetch) {
		    sym_get(sym);
		    r->mavis_pap_prefetch = TRISTATE_YES;
		}
		r->mavis_pap = TRISTATE_YES;
		r->mavis_userdb = TRISTATE_YES;
		break;
	    case S_password:
		sym_get(sym);
		parse(sym, S_equal);
		switch (sym->code) {
		case S_pap:
		    r->default_host->map_pap_to_login = TRISTATE_NO;
		    break;
		case S_login:
		    r->default_host->map_pap_to_login = TRISTATE_YES;
		    break;
		default:
		    parse_error_expect(sym, S_login, S_pap, S_unknown);
		}
		sym_get(sym);
		continue;
	    default:
		parse_error_expect(sym, S_backend, S_login, S_unknown);
	    }
	    continue;
	case S_login:
	    sym_get(sym);
	    parse(sym, S_backend);
	    parse(sym, S_equal);
	    parse(sym, S_mavis);
	    while (1) {
		switch (sym->code) {
		case S_prefetch:
		    sym_get(sym);
		    r->mavis_login_prefetch = TRISTATE_YES;
		    continue;
		case S_chalresp:
		    sym_get(sym);
		    r->chalresp = TRISTATE_YES;
		    if (sym->code == S_noecho) {
			sym_get(sym);
			r->chalresp_noecho = TRISTATE_YES;
		    }
		    continue;
		case S_chpass:
		    sym_get(sym);
		    r->chpass = TRISTATE_YES;
		    continue;
		default:;
		}
		break;
	    }
	    r->mavis_login = TRISTATE_YES;
	    r->mavis_userdb = TRISTATE_YES;
	    continue;
	case S_accounting:
	    sym_get(sym);
	    parse(sym, S_log);
	    parse(sym, S_equal);
	    log_add(sym, &r->acctlog, sym->buf, r);
	    sym_get(sym);
	    continue;
	case S_authentication:
	    sym_get(sym);
	    switch (sym->code) {
	    case S_log:
		parse(sym, S_equal);
		log_add(sym, &r->accesslog, sym->buf, r);
		sym_get(sym);
		continue;
	    case S_fallback:
		sym_get(sym);
		parse(sym, S_equal);
		r->default_host->authfallback = parse_tristate(sym);
		continue;
	    default:
		parse_error_expect(sym, S_log, S_fallback, S_unknown);
	    }
	case S_access:
	    sym_get(sym);
	    parse(sym, S_log);
	    parse(sym, S_equal);
	    log_add(sym, &r->accesslog, sym->buf, r);
	    sym_get(sym);
	    continue;
	case S_authorization:
	    sym_get(sym);
	    parse(sym, S_log);
	    parse(sym, S_equal);
	    log_add(sym, &r->authorlog, sym->buf, r);
	    sym_get(sym);
	    continue;
	case S_warning:
	    sym_get(sym);
	    parse(sym, S_period);
	    parse(sym, S_equal);
	    r->warning_period = parse_seconds(sym);
	    if (r->warning_period < 60)
		r->warning_period *= 86400;
	    continue;
	case S_connection:
	    sym_get(sym);
	    switch (sym->code) {
	    case S_timeout:
		sym_get(sym);
		parse(sym, S_equal);
		r->default_host->tcp_timeout = parse_seconds(sym);
		break;
	    case S_log:
		sym_get(sym);
		parse(sym, S_equal);
		log_add(sym, &r->connlog, sym->buf, r);
		sym_get(sym);
		break;
	    default:
		parse_error_expect(sym, S_timeout, S_log, S_unknown);
	    }
	    continue;
	case S_session:
	    sym_get(sym);
	    parse(sym, S_timeout);
	    parse(sym, S_equal);
	    r->default_host->session_timeout = parse_seconds(sym);
	    continue;
	case S_dns:
	    top_only(sym, r);
	    sym_get(sym);
	    switch (sym->code) {
	    case S_preload:
		sym_get(sym);
		switch (sym->code) {
		case S_file:
		    {
			glob_t globbuf;
			int i;

			sym_get(sym);
			parse(sym, S_equal);
			// dns preload file = /etc/hosts

			memset(&globbuf, 0, sizeof(globbuf));

			globerror_sym = sym;

			switch (glob(sym->buf, GLOB_ERR | GLOB_NOESCAPE | GLOB_NOMAGIC | GLOB_BRACE, globerror, &globbuf)) {
			case 0:
			    for (i = 0; i < (int) globbuf.gl_pathc; i++)
				parse_etc_hosts(globbuf.gl_pathv[i], r);
			    break;
#ifdef GLOB_NOMATCH
			case GLOB_NOMATCH:
			    globerror(sym->buf, ENOENT);
			    break;
#endif				/* GLOB_NOMATCH */
			default:
			    parse_etc_hosts(sym->buf, r);
			    globfree(&globbuf);
			}
			sym_get(sym);
			continue;
		    }
		case S_address:
		    {
			// dns preload address $ip = $name
			struct in6_addr a;
			int cm = 128;

			parse(sym, S_address);

			if (v6_ptoh(&a, &cm, sym->buf))
			    parse_error(sym, "Expected an IP address or network in CIDR notation, but got '%s'.", sym->buf);
			sym_get(sym);
			parse(sym, S_equal);

			radix_add(dns_tree_ptr_static, &a, cm, strdup(sym->buf));

			sym_get(sym);
			continue;
		    }
		default:
		    parse_error_expect(sym, S_address, S_file, S_unknown);
		}
	    default:
		parse_error_expect(sym, S_preload, S_unknown);
	    }
	    continue;
	case S_cache:
	    sym_get(sym);
	    parse(sym, S_timeout);
	    parse(sym, S_equal);
	    r->caching_period = parse_seconds(sym);
	    continue;
	case S_log:
	    sym_get(sym);
	    parse_log(sym, r);
	    continue;
	case S_umask:
	    top_only(sym, r);
	    parse_umask(sym, &config.mask);
	    continue;
	case S_retire:
	    top_only(sym, r);
	    sym_get(sym);
	    switch (sym->code) {
	    case S_limit:
		sym_get(sym);
		parse(sym, S_equal);
		config.retire = parse_int(sym);
		continue;
	    case S_timeout:
		sym_get(sym);
		parse(sym, S_equal);
		config.suicide = parse_seconds(sym) + io_now.tv_sec;
		continue;
	    default:
		parse_error_expect(sym, S_limit, S_timeout, S_unknown);
	    }
	    continue;
	case S_user:
	    parse_user(sym, r);
	    continue;
	case S_group:
	    parse_group(sym, r, 0);
	    continue;
	case S_profile:
	    parse_profile(sym, r);
	    continue;
	case S_acl:
	    parse_tac_acl(sym, r);
	    continue;
	case S_mavis:
	    sym_get(sym);
	    switch (sym->code) {
	    case S_module:
		if (parse_mavismodule(&r->mcx, common_data.io, sym))
		    scm_fatal();
		continue;
	    case S_path:
		parse_mavispath(sym);
		continue;
	    case S_cache:
		sym_get(sym);
		parse(sym, S_timeout);
		parse(sym, S_equal);
		r->caching_period = parse_seconds(sym);
		continue;
	    case S_noauthcache:
		sym_get(sym);
		r->mavis_noauthcache = TRISTATE_YES;
		continue;
	    case S_user:
		sym_get(sym);
		parse(sym, S_filter);
		parse(sym, S_equal);
		r->mavis_user_acl = tac_acl_lookup(sym->buf, r);
		if (!r->mavis_user_acl)
		    parse_error(sym, "ACL '%s' not found)", sym->buf);
		sym_get(sym);
		continue;
	    default:
		parse_error_expect(sym, S_module, S_path, S_cache, S_unknown);
	    }
	case S_enable:
	    sym_get(sym);
	    parse(sym, S_user);
	    parse(sym, S_acl);
	    parse(sym, S_equal);
	    r->enable_user_acl = tac_acl_lookup(sym->buf, r);
	    if (!r->enable_user_acl)
		parse_error(sym, "ACL '%s' not found)", sym->buf);
	    sym_get(sym);
	    continue;
	case S_host:
	    parse_host(sym, r, r->default_host);
	    continue;
	case S_net:
	    parse_net(sym, r, NULL);
	    continue;
	case S_parent:
	    sym_get(sym);
	    parse(sym, S_equal);
	    r->parent = lookup_realm(sym->buf, config.default_realm);
	    if (!r->parent)
		parse_error(sym, "realm '%s' not found", sym->buf);
	    if (loopcheck_realm(r))
		parse_error(sym, "'%s': circular reference rejected", sym->buf);
	    sym_get(sym);
	    continue;
	case S_ruleset:
	    parse_ruleset(sym, r);
	    continue;
	case S_timespec:
	    if (!r->timespectable)
		r->timespectable = init_timespec();
	    parse_timespec(r->timespectable, sym);
	    continue;
	case S_time:
	    sym_get(sym);
	    parse(sym, S_zone);
	    parse(sym, S_equal);
	    setenv("TZ", sym->buf, 1);
	    tzset();
	    sym_get(sym);
	    continue;
	case S_realm:
	    {
		tac_realm *newrealm, *rp;
		char *name;
		sym_get(sym);
		if ((rp = lookup_realm(sym->buf, config.default_realm)))
		    parse_error(sym, "Realm '%s' already defined at line %u", sym->buf, rp->line);
		if (!r->realms)
		    r->realms = RB_tree_new(compare_realm, NULL);
		name = strdup(sym->buf);
		sym_get(sym);
		parse(sym, S_openbra);
		newrealm = parse_realm(sym, name, r);
		parse(sym, S_closebra);
		RB_insert(r->realms, newrealm);
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
	case S_anonenable:
	case S_key:
	case S_motd:
	case S_welcome:
	case S_reject:
	case S_permit:
	case S_bug:
	case S_augmented_enable:
	case S_singleconnection:
	case S_context:
	case S_script:
	case S_ssh_key_check:
	    parse_host_attr(sym, r, r->default_host);
	    continue;
#ifdef WITH_TLS
	case S_tls:
	    sym_get(sym);
	    switch (sym->code) {
	    case S_cert_file:
		sym_get(sym);
		parse(sym, S_equal);
		r->tls_cert = strdup(sym->buf);
		sym_get(sym);
		continue;
	    case S_key_file:
		sym_get(sym);
		parse(sym, S_equal);
		r->tls_key = strdup(sym->buf);
		sym_get(sym);
		continue;
	    case S_cafile:
		sym_get(sym);
		parse(sym, S_equal);
		r->tls_cafile = strdup(sym->buf);
		sym_get(sym);
		continue;
	    case S_passphrase:
		sym_get(sym);
		parse(sym, S_equal);
		r->tls_pass = strdup(sym->buf);
		sym_get(sym);
		continue;
	    case S_ciphers:
		sym_get(sym);
		parse(sym, S_equal);
		r->tls_ciphers = strdup(sym->buf);
		sym_get(sym);
		continue;
	    case S_accept:
		sym_get(sym);
		parse(sym, S_expired);
		parse(sym, S_equal);
		r->tls_accept_expired = parse_tristate(sym);
		continue;
	    default:
		parse_error_expect(sym, S_cert_file, S_key_file, S_cafile, S_passphrase, S_ciphers, S_peer, S_accept, S_unknown);
	    }
	    continue;
#endif
	case S_syslog:
	case S_proctitle:
	case S_coredump:
	case S_alias:
	    top_only(sym, r);
	    parse_common(sym);
	    continue;
	default:
	    parse_error(sym, "Unrecognized token '%s'", sym->buf);
	}
#ifdef WITH_TLS
    if ((r->tls_cert || r->tls_key || r->tls_cafile) && (!r->tls_cert || !r->tls_key || !r->tls_cafile))
	parse_error(sym, "TLS configuration for realm %s is incomplete", r->name);
#endif
}

void parse_decls(struct sym *sym)
{
    config.default_realm = parse_realm(sym, "default", NULL);
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
	sym_get(sym);
	return mktime(&tm) + offset;
    }
    if (1 == sscanf(sym->buf, "%lld", &ll)) {
	sym_get(sym);
	return (time_t) ll;
    }
    parse_error(sym, "Unrecognized date '%s' (expected format: YYYY-MM-DD)", sym->buf);

    return (time_t) 0;
}

void free_user(tac_user * user)
{
    if (user->avc)
	av_free(user->avc);
    memlist_destroy(user->memlist);
}

struct groups_s;
static struct pwdat *passwd_deny = NULL;
static struct pwdat *passwd_mavis = NULL;
static struct pwdat *passwd_login = NULL;
static struct pwdat *passwd_deny_dflt = NULL;
static struct pwdat *passwd_mavis_dflt = NULL;
static struct pwdat *passwd_login_dflt = NULL;
static struct pwdat *passwd_permit = NULL;

tac_user *new_user(char *name, enum token type, tac_realm * r)
{
    memlist_t *memlist = NULL;
    tac_user *user;

    report(NULL, LOG_DEBUG, DEBUG_CONFIG_FLAG, "creating user %s in realm %s", name, r->name);

    if (type != S_user)
	memlist = memlist_create();
    user = memlist_malloc(memlist, sizeof(tac_user));
    user->name = memlist_strdup(memlist, name);
    user->name_len = strlen(name);
    user->memlist = memlist;
    user->realm = r;
    user->chalresp = TRISTATE_DUNNO;
    user->hushlogin = TRISTATE_DUNNO;

    return user;
}

tac_profile *new_profile(char *name, tac_realm * r)
{
    tac_profile *profile;

    report(NULL, LOG_DEBUG, DEBUG_CONFIG_FLAG, "creating profile %s in realm %s", name, r->name);

    profile = (tac_profile *) calloc(1, sizeof(tac_profile));
    profile->name = strdup(name);
    profile->name_len = strlen(name);
    profile->realm = r;
    profile->hushlogin = TRISTATE_DUNNO;
    return profile;
}

static void parse_group(struct sym *sym, tac_realm * r, tac_group * parent)
{
    tac_group *g, *ng = 0;

    sym_get(sym);

    if (sym->code == S_equal)
	sym_get(sym);

    g = tac_group_new(sym, sym->buf, r);
    g->line = sym->line;

    sym_get(sym);
    g->parent = parent;

    if (sym->code == S_openbra) {
	sym_get(sym);

	while (sym->code != S_closebra)
	    switch (sym->code) {
	    case S_group:
		parse_group(sym, r, g);
		continue;
	    case S_parent:
		sym_get(sym);
		parse(sym, S_equal);
		ng = lookup_group(sym->buf, r);
		if (!ng)
		    parse_error(sym, "Group '%s' not found.", sym->buf);
		g->parent = ng->parent;
		if (loopcheck_group(g))
		    parse_error(sym, "'%s': circular reference rejected", sym->buf);
		sym_get(sym);
		continue;
	    default:
		parse_error_expect(sym, S_group, S_parent, S_unknown);
	    }
	sym_get(sym);
    }
}

static void parse_profile(struct sym *sym, tac_realm * r)
{
    tac_profile *n, *profile;

    if (!r->profiletable)
	r->profiletable = RB_tree_new(compare_profile, NULL);

    sym_get(sym);

    if (sym->code == S_equal)
	sym_get(sym);
    profile = new_profile(sym->buf, r);

    n = (tac_profile *) RB_lookup(r->profiletable, (void *) profile);
    if (n)
	parse_error(sym, "Profile '%s' already defined at line %u", profile->name, n->line);

    profile->line = sym->line;
    sym_get(sym);
    parse_profile_attr(sym, profile, r);
    RB_insert(r->profiletable, profile);
}


static struct tac_script_action *tac_script_parse_r(struct sym *, int, tac_realm *);

static void parse_ruleset(struct sym *sym, tac_realm * realm)
{
    tac_profile profile;
    memset(&profile, 0, sizeof(tac_profile));
    profile.realm = realm;

    struct tac_rule **r = &(realm->rules);
    while (*r)
	r = &(*r)->next;

    sym_get(sym);
    if (sym->code == S_equal)
	sym_get(sym);
    parse(sym, S_openbra);

    while (sym->code == S_rule) {
	char *rulename = NULL;
	char synthname[SCM_REALM_SIZE + 16];
	sym_get(sym);
	if (sym->code == S_openbra) {
	    rulename = synthname;
	    snprintf(synthname, sizeof(synthname), "%s#%d", realm->name, realm->rulecount++);
	    // no rule name
	} else
	    rulename = sym->buf;

	*r = calloc(1, sizeof(struct tac_rule));
	(*r)->acl.name = strdup(rulename);
	(*r)->enabled = 1;	// enabled by default
	if (rulename == sym->buf)
	    sym_get(sym);

	parse(sym, S_openbra);

	while (sym->code != S_closebra) {
	    switch (sym->code) {
	    case S_enabled:
		sym_get(sym);
		parse(sym, S_equal);
		(*r)->enabled = parse_bool(sym);
		continue;
	    case S_script:
		sym_get(sym);
		parse(sym, S_openbra);

		struct tac_script_action **p = &(*r)->acl.action;

		while (*p)
		    p = &(*p)->n;

		*p = tac_script_parse_r(sym, 1, realm);

		parse(sym, S_closebra);

		continue;
	    default:
		parse_error_expect(sym, S_enabled, S_script, S_unknown);
	    }
	}
	sym_get(sym);
	r = &(*r)->next;
    }
    parse(sym, S_closebra);
}

static enum token lookup_user_profile(tac_session * session)
{
    int i;
    for (i = 0; i < USER_PROFILE_CACHE_SIZE; i++) {
	if (session->ctx->user_profile_cache[i].user == session->user) {
	    if (session->ctx->user_profile_cache[i].valid_until >= io_now.tv_sec) {
		session->profile = session->ctx->user_profile_cache[i].profile;
		return session->ctx->user_profile_cache[i].res;
	    }
	    session->ctx->user_profile_cache[i].user = NULL;
	    session->ctx->user_profile_cache[i].profile = NULL;
	    return S_unknown;
	}
    }
    return S_unknown;
}

static void cache_user_profile(tac_session * session, enum token res)
{
    int i, j = 0;

    for (i = 0; i < USER_PROFILE_CACHE_SIZE; i++) {
	if (session->ctx->user_profile_cache[i].user == session->user) {
	    j = i;
	    goto set;
	}
    }
    for (i = 0; i < USER_PROFILE_CACHE_SIZE; i++) {
	if (session->ctx->user_profile_cache[j].valid_until > session->ctx->user_profile_cache[i].valid_until)
	    j = i;
	if (session->ctx->user_profile_cache[i].valid_until < io_now.tv_sec) {
	    j = i;
	    goto set;
	}
    }
  set:
    session->ctx->user_profile_cache[j].user = session->user;
    session->ctx->user_profile_cache[j].profile = session->profile;
    session->ctx->user_profile_cache[j].res = res;
    session->ctx->user_profile_cache[j].valid_until = io_now.tv_sec + 120;
}


enum token eval_ruleset(tac_session * session, tac_realm * realm)
{
    enum token res = lookup_user_profile(session);
    if (res != S_unknown) {
	report(session, LOG_DEBUG, DEBUG_ACL_FLAG | DEBUG_REGEX_FLAG,
	       "%s@%s: cached: %s (profile: %s)", session->username, session->nac_address_ascii, codestring[res],
	       session->profile ? session->profile->name : "n/a");
	return res;
    }

    while (realm) {
	struct tac_rule *rule = realm->rules;
	while (rule) {
	    if (rule->enabled) {
		res = eval_tac_acl(session, &rule->acl);
		report(session, LOG_DEBUG, DEBUG_ACL_FLAG | DEBUG_REGEX_FLAG,
		       "%s@%s: ACL %s: %s (profile: %s)", session->username, session->nac_address_ascii, rule->acl.name, codestring[res],
		       session->profile ? session->profile->name : "n/a");
		switch (res) {
		case S_permit:
		case S_deny:
		    cache_user_profile(session, res);
		    session->rule = rule->acl.name;
		    session->rule_len = rule->acl.name_len;
		    return res;
		default:;
		}
	    }
	    rule = rule->next;
	}
	realm = realm->parent;
    }
    return S_deny;
}


static void parse_user(struct sym *sym, tac_realm * r)
{
    tac_user *n, *user;
    enum token type = sym->code;

    if (!r->usertable)
	r->usertable = RB_tree_new(compare_user, (void (*)(void *)) free_user);

    sym_get(sym);

    if (sym->code == S_backend) {
	parse(sym, S_backend);
	parse(sym, S_equal);
	switch (sym->code) {
	case S_mavis:
	    r->mavis_userdb = TRISTATE_YES;
	    break;
	case S_local:
	    r->mavis_userdb = TRISTATE_NO;
	    break;
	default:
	    parse_error_expect(sym, S_mavis, S_local, S_unknown);
	}
	sym_get(sym);
	return;
    }

    if (sym->code == S_equal)
	sym_get(sym);
    user = new_user(sym->buf, type, r);
    user->line = sym->line;

    n = (tac_user *) RB_lookup(r->usertable, (void *) user);
    if (n)
	parse_error(sym, "User '%s' already defined at line %u", user->name, n->line);

    sym_get(sym);
    parse_user_attr(sym, user);
    parse_user_final(user);
    RB_insert(r->usertable, user);
    //report(NULL, LOG_INFO, ~0, "user %s added to realm %s", user->name, r->name);
}

int parse_user_profile(struct sym *sym, tac_user * user)
{
    sym->env_valid = 1;
    if (setjmp(sym->env))
	return -1;
    sym_init(sym);
    parse_user_attr(sym, user);
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


static char hexbyte(char *s)
{
    char *h = "\0\01\02\03\04\05\06\07\010\011\0\0\0\0\0\0\0\012\013\014\015\016\017\0\0\0\0\0\0\0\0\0";
    return (h[(s[0] - '0') & 0x1F] << 4) | h[(s[1] - '0') & 0x1F];
}

static int c7decode(char *in)
{
    int seed;
    char *out = in;
    size_t len = strlen(in);
    static char *c7 = NULL;
    static size_t c7_len = 0;

    if (!c7) {
	char *e = "051207055A0A070E204D4F08180416130A0D052B2A2529323423120617020057585952550F021917585956525354550A5A07065956";
	char *u, *t = e;

	c7 = calloc(1, strlen(e) / 2 + 1);
	u = c7;
	while (*t) {
	    *u = 'a' ^ hexbyte(t);
	    u++, t += 2;
	}
	c7_len = strlen(c7);
    }

    if (len & 1 || len < 4)
	return -1;

    len -= 2;
    seed = 10 * (in[0] - '0') + in[1] - '0';
    in += 2;

    while (len) {
	*out = hexbyte(in) ^ c7[seed % c7_len];
	in += 2, seed++, len -= 2, out++;
    }

    *out = 0;

    return 0;
}

static struct pwdat *parse_pw(struct sym *, memlist_t *, int);

static struct upwdat *new_upwdat(memlist_t * memlist, tac_realm * r)
{
    struct upwdat *pp = memlist_malloc(memlist, sizeof(struct upwdat));
    int i;
    for (i = 0; i <= PW_MAVIS; i++)
	pp->passwd[i] = passwd_deny_dflt;
    if (r->mavis_login == TRISTATE_YES)
	pp->passwd[PW_LOGIN] = passwd_mavis_dflt;
    if (r->mavis_pap == TRISTATE_YES)
	pp->passwd[PW_PAP] = passwd_mavis_dflt;
    if (r->default_host->map_pap_to_login == TRISTATE_YES) {
	if (r->mavis_login == TRISTATE_YES)
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

static struct pwdat *parse_pw(struct sym *sym, memlist_t * memlist, int cry)
{
    struct pwdat *pp = NULL;
    enum token sc;
    int c7 = 0;
    parse(sym, S_equal);

    switch (sym->code) {
    case S_mavis:
	sym_get(sym);
	return passwd_mavis;
    case S_permit:
	sym_get(sym);
	return passwd_permit;
    case S_login:
	sym_get(sym);
	return passwd_login;
    case S_deny:
	sym_get(sym);
	return passwd_deny;
    case S_crypt:
	if (cry)
	    break;
    case S_clear:
	break;
    case S_7:
	sym->code = S_clear;
	c7++;
	break;
    default:
	parse_error_expect(sym, S_clear, S_permit, S_deny, S_login, cry ? S_crypt : S_unknown, S_unknown);
    }

    sc = sym->code;
    sym_get(sym);

    if (c7 && c7decode(sym->buf))
	parse_error(sym, "type 7 password is malformed");

    pp = memlist_malloc(memlist, sizeof(struct pwdat) + strlen(sym->buf));
    pp->type = sc;
    strcpy(pp->value, sym->buf);
    sym_get(sym);
    return pp;
}

static struct pwdat **lookup_pwdat_by_acl(struct sym *sym, tac_user * user, struct tac_acl *a)
{
    struct tac_acllist **pa = &user->passwd_acllist;
    while (*pa && ((*pa)->acl != a)) {
	if (a && !(*pa)->acl)
	    parse_error_order(sym, "password");
	pa = &(*pa)->next;
    }
    if (!(*pa)) {
	*pa = memlist_malloc(user->memlist, sizeof(struct tac_acllist));
	(*pa)->u.passwdp = new_upwdat(user->memlist, user->realm);
	(*pa)->acl = a;
    }
    if ((*pa)->next)
	parse_error_order(sym, "password");

    return (*pa)->u.passwdp->passwd;
}

static void parse_password(struct sym *sym, tac_user * user)
{
    struct tac_acl *a = NULL;
    struct pwdat **pp;
    enum pw_ix pw_ix = 0;
    int one = 0;

    sym_get(sym);

    if (sym->code == S_acl) {
	sym_get(sym);
	a = tac_acl_lookup(sym->buf, user->realm);
	if (!a)
	    parse_error(sym, "ACL '%s' not found (user: %s)", sym->buf, user->name);
	sym_get(sym);
    }

    switch (sym->code) {
    case S_login:
    case S_pap:
    case S_chap:
    case S_mschap:
	one = 1;
    default:;
    }

    if (one || sym->code == S_openbra) {
	if (!one)
	    sym_get(sym);

	pp = lookup_pwdat_by_acl(sym, user, a);

	while (sym->code != S_closebra) {
	    int cry = 0;
	    switch (sym->code) {
	    case S_login:
		pw_ix = PW_LOGIN, cry = 1;
		break;
	    case S_pap:
		pw_ix = PW_PAP, cry = 1;
		break;
	    case S_chap:
		pw_ix = PW_CHAP;
		break;
	    case S_mschap:
		pw_ix = PW_MSCHAP;
		break;
	    default:
		parse_error_expect(sym, S_login, S_pap, S_chap, S_mschap, one ? S_unknown : S_closebra, S_unknown);
	    }
	    sym_get(sym);
	    pp[pw_ix] = parse_pw(sym, user->memlist, cry);
	    if (one)
		break;
	}
	if (!one)
	    sym_get(sym);
    } else
	parse_error_expect(sym, S_login, S_pap, S_chap, S_mschap, S_openbra, S_unknown);
}

static struct tac_acl *tac_acl_lookup(char *s, tac_realm * r)
{
    struct tac_acl a;
    a.name = s;
    while (r) {
	if (r->acltable) {
	    struct tac_acl *res;
	    if ((res = RB_lookup(r->acltable, &a)))
		return res;
	}
	r = r->parent;
    }
    return NULL;
}

static void parse_member(struct sym *sym, tac_groups ** groups, memlist_t * memlist, tac_realm * r)
{
    sym_get(sym);

    parse(sym, S_equal);
    if (!*groups)
	*groups = memlist ? memlist_malloc(memlist, sizeof(tac_groups)) : calloc(1, sizeof(tac_groups));

    do {
	tac_group *g = lookup_group(sym->buf, r);
	if (g)
	    tac_group_add(g, *groups, memlist);
	else
	    parse_error(sym, "Group '%s' not found.", sym->buf);


	sym_get(sym);
    }
    while (parse_comma(sym));
}

static void parse_enable(struct sym *sym, memlist_t * memlist, struct pwdat **enable, char *enable_implied)
{
    int level = TAC_PLUS_PRIV_LVL_MAX, i;

    sym_get(sym);
    if (1 == sscanf(sym->buf, "%d", &level)) {
	if (level < TAC_PLUS_PRIV_LVL_MIN)
	    level = TAC_PLUS_PRIV_LVL_MIN;
	else if (level > TAC_PLUS_PRIV_LVL_MAX)
	    level = TAC_PLUS_PRIV_LVL_MAX;
	sym_get(sym);
    }

    enable[level] = parse_pw(sym, memlist, 1);
    enable_implied[level] = 0;
    for (i = level - 1; i >= TAC_PLUS_PRIV_LVL_MIN; i--) {
	if (enable_implied[i] > level || !enable[i]) {
	    enable_implied[i] = level;
	    enable[i] = enable[level];
	}
    }
}

static struct tac_acllist *eval_tac_acllist(tac_session *, struct tac_acllist **);

struct upwdat *eval_passwd_acl(tac_session * session)
{
    if (session->user) {
	struct tac_acllist *a = eval_tac_acllist(session, &session->user->passwd_acllist);
	if (a)
	    return a->u.passwdp;

	session->user->passwd_acllist = memlist_malloc(session->user->memlist, sizeof(struct tac_acllist));
	session->user->passwd_acllist->u.passwdp = new_upwdat(session->user->memlist, session->user->realm);
	return session->user->passwd_acllist->u.passwdp;
    }
    // shouldn't happen
    return new_upwdat(session->memlist, session->ctx->realm);
}

void parse_user_final(tac_user * user)
{
    struct tac_acllist **pa = &user->passwd_acllist;
    while (*pa && (*pa)->acl)
	pa = &(*pa)->next;
    if (!*pa) {
	*pa = memlist_malloc(user->memlist, sizeof(struct tac_acllist));
	(*pa)->u.passwdp = new_upwdat(user->memlist, user->realm);
    }
}

static void parse_profile_attr(struct sym *sym, tac_profile * profile, tac_realm * r)
{
    struct tac_script_action **p;

    parse(sym, S_openbra);

    while (sym->code != S_closebra)
	switch (sym->code) {
	case S_script:
	    sym_get(sym);
	    p = &profile->action;
	    while (*p)
		p = &(*p)->n;
	    *p = tac_script_parse_r(sym, 0, r);
	    continue;
	case S_debug:
	    sym_get(sym);
	    parse(sym, S_equal);
	    parse_debug(sym, &profile->debug);
	    continue;
	case S_hushlogin:
	    sym_get(sym);
	    parse(sym, S_equal);
	    profile->hushlogin = parse_tristate(sym);
	    continue;
	case S_enable:
	    parse_enable(sym, NULL, profile->enable, profile->enable_implied);
	    continue;
	default:
	    parse_error_expect(sym, S_script, S_debug, S_hushlogin, S_enable, S_unknown);
	}
    sym_get(sym);
}

#ifdef TPNG_EXPERIMENTAL
struct ssh_key_hash {
    struct ssh_key_hash *next;
    char hash[1];
};

// FIXME
//
// MD5 hashing is what IOS currently uses internally. In the CLI config the
// hash gets represented as a sequence of hex bytes.
//
// As there's no standard representation for SSH hashes it might be advisable
// to run a normalizing compare function instead of just strcmp().
//
// Sample Perl normalization code (and probably reusable for PCRE) for MD5 hash normalization:
//
// if ($key =~ /(([\da-f]{2}:?){16})( |$)/i) {
//     my $raw = lc $1;
//     $raw =~ s/://g;
// }
//
// On the other hand, it might make sense to ignore what routers currently do and
// take the ssh-keygen fingerprint as a reference:
// MD5:00:01:02:03:04:...:0E:0F
// SHA256:<base64>
//
// Also, giving the router the option to send more than one fingerprint seems appropriate.
// The server then has the option to require one or more fingerprints to match, e.g.
// MD5 *and* SHA256.
//

enum token validate_ssh_hash(tac_session * session, char *hash)
{
    enum token res = S_deny;
    if (!hash)
	return S_deny;

    while (*hash) {
	// assumption: NAD may return multiple keys, separated by comma or semicolon
	struct ssh_key_hash **ssh_key_hash = &session->user->ssh_key_hash;
	char *next;
	size_t len;
	for (next = hash; *next && *next != ',' && *next != ';'; next++);
	len = next - hash;
	if (*next)
	    next++;
	while (*ssh_key_hash) {
	    if (!strncmp((*ssh_key_hash)->hash, hash, len) && (!hash[len] || hash[len] == ',')) {
		if (session->ctx->host->ssh_key_check_all != TRISTATE_YES)
		    return S_permit;
		res = S_permit;
		break;		// while
	    }
	    ssh_key_hash = &((*ssh_key_hash)->next);
	}
	if ((session->ctx->host->ssh_key_check_all == TRISTATE_YES) && !*ssh_key_hash)
	    return S_deny;
	hash = next;
    }
    return res;
}

static void parse_sshkeyhash(struct sym *sym, tac_user * user)
{
    struct ssh_key_hash **ssh_key_hash = &user->ssh_key_hash;
    while (*ssh_key_hash)
	ssh_key_hash = &((*ssh_key_hash)->next);

    do {
	size_t len;
	len = strlen(sym->buf);
	*ssh_key_hash = memlist_malloc(user->memlist, sizeof(struct ssh_key_hash) + len);
	memcpy((*ssh_key_hash)->hash, sym->buf, len + 1);
	sym_get(sym);
	ssh_key_hash = &((*ssh_key_hash)->next);
    } while (parse_comma(sym));
}

#ifdef WITH_SSL
#include <openssl/evp.h>

static char *calc_ssh_key_hash(char *hashname, unsigned char *in, size_t in_len)
{
    static unsigned char out[512];
    unsigned char md[256];
    size_t md_len = sizeof(md);
    size_t hashname_len;
    unsigned char *o;
    char *t = strchr(hashname, ':');
    if (t) {
	// <HASHNAME>:<HASH> => <HASHNAME>
	ssize_t len = t - hashname;
	t = alloca(len);
	len--;
	t[len] = 0;
	while (len > -1) {
	    len--;
	    t[len] = hashname[len];
	}
	hashname = t;
    }
    if (!in_len)
	in_len = strlen((char *) in);
    if (!EVP_Q_digest(NULL, hashname, NULL, in, in_len, md, &md_len))
	return NULL;

    if (!strcmp(hashname, "MD5")) {
	char hex[] = "0123456789abcdef";
	o = out;
	int i;
	*o++ = 'M';
	*o++ = 'D';
	*o++ = '5';
	*o++ = ':';
	for (i = 0; i < 16; i++) {
	    *o++ = hex[md[i] >> 4];
	    *o++ = hex[md[i] & 15];
	    *o++ = (i < 15) ? ':' : 0;
	}
	return (char *) out;
    }

    hashname_len = strlen(hashname);
    strncpy((char *) out, hashname, hashname_len);
    o = out + hashname_len;
    *o++ = ':';
    if (EVP_EncodeBlock(o, md, md_len))
	return (char *) out;

    return NULL;
}

static void parse_sshkey(struct sym *sym, tac_user * user)
{
    struct ssh_key_hash **ssh_key_hash = &user->ssh_key_hash;

    while (*ssh_key_hash)
	ssh_key_hash = &((*ssh_key_hash)->next);

    do {
	size_t slen = strlen(sym->buf);
	unsigned char *t = alloca(slen);
	char *hash;
	size_t hash_len;
	int len = EVP_DecodeBlock(t, (const unsigned char *) sym->buf, slen);
	int pad = 0;

	if (len < 4)
	    parse_error(sym, "BASE64 decode of SSH key failed.");

	if (sym->buf[slen - 1] == '=')
	    pad++;
	if (sym->buf[slen - 2] == '=')
	    pad++;
	len = (slen * 3) / 4 - pad;

	hash = calc_ssh_key_hash("MD5", t, len);
	if (!hash)
	    parse_error(sym, "MD5 hashing failed.");
	hash_len = strlen(hash);
	*ssh_key_hash = memlist_malloc(user->memlist, sizeof(struct ssh_key_hash) + len);
	memcpy((*ssh_key_hash)->hash, hash, len + 1);
	ssh_key_hash = &((*ssh_key_hash)->next);

	hash = calc_ssh_key_hash("SHA256", t, len);
	if (!hash)
	    parse_error(sym, "SHA256 hashing failed.");
	hash_len = strlen(hash);
	while (hash[hash_len - 1] == '=') {
	    hash_len--;
	    hash[hash_len] = 0;
	}
	*ssh_key_hash = memlist_malloc(user->memlist, sizeof(struct ssh_key_hash) + len);
	memcpy((*ssh_key_hash)->hash, hash, len + 1);

	sym_get(sym);
	ssh_key_hash = &((*ssh_key_hash)->next);

    } while (parse_comma(sym));
}
#endif				// WITH_SSL

#endif

static void parse_user_attr(struct sym *sym, tac_user * user)
{
    tac_realm *r = user->realm;

    parse(sym, S_openbra);

    while (sym->code != S_closebra) {
	switch (sym->code) {
	case S_member:
	    parse_member(sym, &user->groups, user->memlist, r);
	    continue;
	case S_valid:
	    sym_get(sym);
	    switch (sym->code) {
	    case S_until:
		sym_get(sym);
		parse(sym, S_equal);
		user->valid_until = parse_date(sym, 86400);
		break;
	    case S_from:
		sym_get(sym);
	    default:
		parse(sym, S_equal);
		user->valid_from = parse_date(sym, 0);
		break;
	    }
	    continue;
	case S_debug:
	    sym_get(sym);
	    parse(sym, S_equal);
	    parse_debug(sym, &user->debug);
	    continue;
	case S_message:
	    sym_get(sym);
	    parse(sym, S_equal);
	    user->msg = memlist_strdup(user->memlist, sym->buf);
	    sym_get(sym);
	    continue;
	case S_password:
	    parse_password(sym, user);
	    continue;
	case S_enable:
	    parse_enable(sym, user->memlist, user->enable, user->enable_implied);
	    continue;
	case S_fallback_only:
	    sym_get(sym);
	    user->fallback_only = 1;
	    continue;
	case S_hushlogin:
	    sym_get(sym);
	    parse(sym, S_equal);
	    user->hushlogin = parse_tristate(sym);
	    continue;
#ifdef TPNG_EXPERIMENTAL
	case S_ssh_key_hash:
	    sym_get(sym);
	    parse(sym, S_equal);
	    parse_sshkeyhash(sym, user);
	    continue;
#ifdef WITH_SSL
	case S_ssh_key:
	    sym_get(sym);
	    parse(sym, S_equal);
	    parse_sshkey(sym, user);
	    continue;
#endif
#endif
	default:
	    parse_error_expect(sym, S_member, S_valid, S_debug, S_message, S_password, S_enable, S_fallback_only, S_hushlogin, S_unknown);
	}
    }
    sym_get(sym);
}

static void add_host(struct sym *sym, radixtree_t * ht, tac_host * host)
{
    struct in6_addr a;
    tac_host *h;
    int cm;
    if (v6_ptoh(&a, &cm, sym->buf))
	parse_error(sym, "Expected an IP address or network in CIDR notation, but got '%s'.", sym->buf);

    if (ht && (h = radix_add(ht, &a, cm, host)))
	parse_error(sym, "Address '%s' already assigned to host '%s'.", sym->buf, h->name);
}

static void add_net(struct sym *sym, radixtree_t * ht, tac_net * net)
{
    struct in6_addr a;
    int cm;
    if (v6_ptoh(&a, &cm, sym->buf))
	parse_error(sym, "Expected an IP address or network in CIDR notation, but got '%s'.", sym->buf);

    radix_add(ht, &a, cm, net);
}

static void parse_file(char *url, radixtree_t * ht, tac_host * host, tac_net * net)
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
	if (host)
	    add_host(&sym, ht, host);
	if (net)
	    add_net(&sym, ht, net);
	sym_get(&sym);
    }

    cfg_close(url, buf, bufsize);
}

static void parse_rewrite(struct sym *sym, tac_realm * r)
{
    tac_rewrite_expr **e;
    tac_rewrite *rewrite = alloca(sizeof(tac_rewrite));

    if (!r->rewrite)
	r->rewrite = RB_tree_new(compare_rewrite, NULL);

    rewrite->name = sym->buf;
    rewrite = RB_lookup(r->rewrite, rewrite);
    if (!rewrite) {
	rewrite = (tac_rewrite *) calloc(1, sizeof(tac_rewrite));
	rewrite->name = strdup(sym->buf);
	RB_insert(r->rewrite, rewrite);
    }

    sym_get(sym);
    if (sym->code == S_equal)
	sym_get(sym);

    e = &rewrite->expr;
    while (*e)
	e = &(*e)->next;

    parse(sym, S_openbra);
    while (sym->code == S_rewrite) {
#ifdef WITH_PCRE2
	int errcode = 0;
	*e = (tac_rewrite_expr *) calloc(1, sizeof(tac_rewrite_expr));
	sym->flag_parse_pcre = 1;
	sym_get(sym);
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
	    sym_get(sym);
	    (*e)->replacement = (PCRE2_SPTR) strdup(sym->buf);
	    e = &(*e)->next;
	    sym_get(sym);
	}
#else
	parse_error(sym, "You're using a PCREv2-only feature, but this binary wasn't compiled with PCREv2 support.");
#endif
    }
    sym->flag_parse_pcre = 0;
    parse(sym, S_closebra);
}

static void fixup_banner(struct log_item **li, char *file, int line)
{
    while (*li)
	li = &(*li)->next;
    *li = parse_log_format_inline("\"${message}${umessage}\"", file, line);
}

static void parse_host_attr(struct sym *sym, tac_realm * r, tac_host * host)
{
    switch (sym->code) {
    case S_host:
	parse_host(sym, r, host);
	return;
    case S_parent:
	sym_get(sym);
	parse(sym, S_equal);
	host->parent = lookup_host(sym->buf, r);
	if (!host->parent)
	    parse_error(sym, "Host '%s' not found.", sym->buf);
	if (loopcheck_host(host))
	    parse_error(sym, "'%s': circular reference rejected", sym->buf);
	sym_get(sym);
	return;
    case S_authentication:
	sym_get(sym);
	switch (sym->code) {
	case S_fallback:
	    sym_get(sym);
	    parse(sym, S_equal);
	    host->authfallback = parse_tristate(sym);
	    break;
	default:
	    parse_error_expect(sym, S_fallback, S_unknown);
	}
	return;
    case S_permit:
	sym_get(sym);
	parse(sym, S_ifauthenticated);
	parse(sym, S_equal);
	host->authz_if_authc = parse_tristate(sym);
	return;
    case S_bug:
	sym_get(sym);
	parse(sym, S_compatibility);
	parse(sym, S_equal);
	host->bug_compatibility = parse_int(sym);
	return;
    case S_pap:
	sym_get(sym);
	switch (sym->code) {
	case S_password:
	    sym_get(sym);
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
	    sym_get(sym);
	    return;
	default:
	    parse_error_expect(sym, S_password, S_unknown);
	}
    case S_address:
	sym_get(sym);
	if (sym->code == S_file) {
	    glob_t globbuf;
	    int i;

	    memset(&globbuf, 0, sizeof(globbuf));
	    sym_get(sym);
	    parse(sym, S_equal);

	    globerror_sym = sym;

	    switch (glob(sym->buf, GLOB_ERR | GLOB_NOESCAPE | GLOB_NOMAGIC | GLOB_BRACE, globerror, &globbuf)) {
	    case 0:
		for (i = 0; i < (int) globbuf.gl_pathc; i++)
		    parse_file(globbuf.gl_pathv[i], r->hosttree, host, NULL);
		break;
#ifdef GLOB_NOMATCH
	    case GLOB_NOMATCH:
		globerror(sym->buf, ENOENT);
		break;
#endif				/* GLOB_NOMATCH */
	    default:
		parse_file(sym->buf, r->hosttree, host, NULL);
		globfree(&globbuf);
	    }
	    sym_get(sym);
	} else {
	    parse(sym, S_equal);
	    do {
		add_host(sym, r->hosttree, host);
		sym_get(sym);
	    }
	    while (parse_comma(sym));
	}
	return;
    case S_key:
	parse_key(sym, &host->key);
	return;
    case S_motd:
	sym_get(sym);
	parse(sym, S_banner);
	parse(sym, S_equal);
	host->motd = parse_log_format(sym);
	fixup_banner(&host->motd, __FILE__, __LINE__);
	return;
    case S_welcome:
	sym_get(sym);
	parse(sym, S_banner);
	if (sym->code == S_fallback) {
	    sym_get(sym);
	    parse(sym, S_equal);
	    host->welcome_banner_fallback = parse_log_format(sym);
	    fixup_banner(&host->welcome_banner_fallback, __FILE__, __LINE__);
	} else {
	    parse(sym, S_equal);
	    host->welcome_banner = parse_log_format(sym);
	    fixup_banner(&host->welcome_banner, __FILE__, __LINE__);
	}
	return;
    case S_reject:
	sym_get(sym);
	parse(sym, S_banner);
	parse(sym, S_equal);
	host->reject_banner = parse_log_format(sym);
	fixup_banner(&host->reject_banner, __FILE__, __LINE__);
	return;
    case S_enable:
	parse_enable(sym, NULL, host->enable, host->enable_implied);
	return;
    case S_anonenable:
	sym_get(sym);
	parse(sym, S_equal);
	host->anon_enable = parse_tristate(sym);
	return;
    case S_augmented_enable:
	sym_get(sym);
	parse(sym, S_equal);
	host->augmented_enable = parse_tristate(sym);
	return;
    case S_singleconnection:
	sym_get(sym);
	switch (sym->code) {
	case S_mayclose:
	    sym_get(sym);
	    parse(sym, S_equal);
	    host->cleanup_when_idle = parse_tristate(sym);
	    break;
	case S_equal:
	    sym_get(sym);
	    host->single_connection = parse_tristate(sym);
	    break;
	default:
	    parse_error_expect(sym, S_mayclose, S_equal, S_unknown);
	}
	return;
    case S_debug:
	sym_get(sym);
	parse(sym, S_equal);
	parse_debug(sym, &host->debug);
	return;
    case S_connection:
	sym_get(sym);
	parse(sym, S_timeout);
	parse(sym, S_equal);
	host->tcp_timeout = parse_seconds(sym);
	return;
    case S_password:
	sym_get(sym);
	parse(sym, S_maxattempts);
	parse(sym, S_equal);
	host->authen_max_attempts = parse_int(sym);
	return;
    case S_context:
	sym_get(sym);
	parse(sym, S_timeout);
	parse(sym, S_equal);
	host->context_timeout = parse_seconds(sym);
	return;
    case S_rewrite:{		// legacy option, will be removed late on
	    sym_get(sym);
	    parse(sym, S_user);
	    if (sym->code == S_equal)
		sym_get(sym);
	    host->rewrite_user = lookup_rewrite(sym->buf, r);
	    if (!host->rewrite_user)
		parse_error(sym, "Rewrite set '%s' not found", sym->buf);
	    sym_get(sym);
	    return;
	}
    case S_script:{
	    struct tac_script_action **p = &host->action;
	    sym_get(sym);
	    while (*p)
		p = &(*p)->n;
	    *p = tac_script_parse_r(sym, 0, r);
	    return;
	}
#ifdef TPNG_EXPERIMENTAL
    case S_ssh_key_check:
	sym_get(sym);
	parse(sym, S_equal);
	switch (sym->code) {
	case S_any:
	    host->ssh_key_check_all = TRISTATE_NO;
	    break;
	case S_all:
	    host->ssh_key_check_all = TRISTATE_YES;
	    break;
	default:
	    parse_error_expect(sym, S_all, S_any, S_unknown);
	}
	sym_get(sym);
	return;
#endif
    default:
	parse_error_expect(sym, S_host, S_parent, S_authentication, S_permit, S_bug, S_pap, S_address, S_key, S_motd, S_welcome, S_reject, S_enable,
			   S_anonenable, S_augmented_enable, S_singleconnection, S_debug, S_connection, S_context, S_rewrite, S_script, S_unknown);
    }
}

static void parse_host(struct sym *sym, tac_realm * r, tac_host * parent)
{
    tac_host *host = (tac_host *) calloc(1, sizeof(tac_host)), *hp;
    radixtree_t *ht;
    struct dns_forward_mapping *d;

    if (!r->hosttable) {
	r->hosttable = RB_tree_new(compare_host, NULL);
	r->hosttree = radix_new(NULL, NULL);
    }

    host->line = sym->line;
    host->parent = parent;

    sym_get(sym);

    host->realm = r;
    ht = r->hosttree;

    if (sym->code == S_equal)
	sym_get(sym);

    host->name = strdup(sym->buf);
    host->name_len = strlen(host->name);
    if (strchr(host->name, '=')) {	// likely a certificate subject. Normalize.
	size_t i;
	for (i = 0; i < host->name_len; i++)
	    host->name[i] = tolower(host->name[i]);
    }
    if ((hp = RB_lookup(r->hosttable, (void *) host)))
	parse_error(sym, "Host '%s' already defined at line %u", sym->buf, hp->line);
    host->line = sym->line;

    d = dns_lookup_a(r, sym->buf, 0);
    while (d) {
	tac_host *exists;
	if (ht && (exists = radix_add(ht, &d->a, 128, host)))
	    parse_error(sym, "Address '%s' already assigned to host '%d'", sym->buf, exists->name);
	d = d->next;
    }

    host->tcp_timeout = -1;
    host->session_timeout = -1;
    host->context_timeout = -1;
    host->authen_max_attempts = -1;

    sym_get(sym);
    parse(sym, S_openbra);

    while (sym->code != S_closebra)
	parse_host_attr(sym, r, host);
    sym_get(sym);
    RB_insert(r->hosttable, host);
}

static void parse_net(struct sym *sym, tac_realm * r, tac_net * parent)
{
    tac_net *net = (tac_net *) calloc(1, sizeof(tac_net)), *np;
    struct dns_forward_mapping *d;

    if (!r->nettable)
	r->nettable = RB_tree_new(compare_net, NULL);

    net->line = sym->line;

    sym_get(sym);

    net->name = strdup(sym->buf);
    net->nettree = radix_new(NULL, NULL);
    if ((np = RB_lookup(r->nettable, (void *) net)))
	parse_error(sym, "Net '%s' already defined at line %u", sym->buf, np->line);
    net->line = sym->line;
    net->parent = parent;
    net->res = S_permit;

    d = dns_lookup_a(r, sym->buf, 1);
    while (d) {
	radix_add(net->nettree, &d->a, 128, net);
	d = d->next;
    }

    sym_get(sym);
    parse(sym, S_openbra);

    while (sym->code != S_closebra)
	switch (sym->code) {
	case S_permit:
	case S_deny:
	    net->res = sym->code;
	    continue;
	case S_address:
	    sym_get(sym);
	    if (sym->code == S_file) {
		glob_t globbuf;
		int i;
		memset(&globbuf, 0, sizeof(globbuf));
		sym_get(sym);
		parse(sym, S_equal);

		globerror_sym = sym;

		switch (glob(sym->buf, GLOB_ERR | GLOB_NOESCAPE | GLOB_NOMAGIC | GLOB_BRACE, globerror, &globbuf)) {
		case 0:
		    for (i = 0; i < (int) globbuf.gl_pathc; i++)
			parse_file(globbuf.gl_pathv[i], net->nettree, NULL, net);
		    break;
#ifdef GLOB_NOMATCH
		case GLOB_NOMATCH:
		    globerror(sym->buf, ENOENT);
		    break;
#endif				/* GLOB_NOMATCH */
		default:
		    parse_file(sym->buf, net->nettree, NULL, net);
		    globfree(&globbuf);
		}
		sym_get(sym);
	    } else {
		parse(sym, S_equal);
		do {
		    add_net(sym, net->nettree, net);
		    sym_get(sym);
		}
		while (parse_comma(sym));
	    }
	    continue;
	case S_net:
	    parse_net(sym, r, net);
	    break;
	case S_parent:
	    sym_get(sym);
	    parse(sym, S_equal);
	    net->parent = lookup_net(sym->buf, r);
	    if (!net->parent)
		parse_error(sym, "Net '%s' not found.", sym->buf);
	    if (loopcheck_net(net))
		parse_error(sym, "'%s': circular reference rejected", sym->buf);
	    sym_get(sym);
	    continue;
	default:
	    parse_error_expect(sym, S_permit, S_deny, S_address, S_net, S_unknown);
	}
    sym_get(sym);
    RB_insert(r->nettable, net);
}

static struct tac_acllist *eval_tac_acllist(tac_session * session, struct tac_acllist **al)
{
    while (*al) {
	if ((*al)->acl) {
	    switch (eval_tac_acl(session, (*al)->acl)) {
	    case S_permit:
		return *al;
	    case S_deny:
		break;
	    default:
		;
	    }
	} else
	    return *al;
	al = &(*al)->next;
    }
    return NULL;
}

enum token eval_tac_acl(tac_session * session, struct tac_acl *acl)
{
    if (acl) {
	char *hint = "";
	enum token res = S_unknown;
	struct tac_script_action *action = acl->action;
	while (action) {
	    switch ((res = tac_script_eval_r(session, action))) {
	    case S_permit:
	    case S_deny:
		return res;
	    default:
		action = action->n;
	    }
	}

	report(session, LOG_DEBUG,
	       DEBUG_ACL_FLAG | DEBUG_REGEX_FLAG,
	       "%s@%s: ACL %s: %smatch%s", session->username, session->nac_address_ascii, acl->name, res == S_permit ? "" : "no ", hint);
    }
    return S_unknown;
}

// acl = <name> [(permit|deny)] { ... }
static void parse_tac_acl(struct sym *sym, tac_realm * realm)
{
    struct tac_acl *a;
    sym_get(sym);

    if (!realm->acltable)
	realm->acltable = RB_tree_new(compare_acl, NULL);

    if (sym->code == S_equal)
	sym_get(sym);

    a = tac_acl_lookup(sym->buf, realm);
    if (!a) {
	size_t l = strlen(sym->buf);
	a = calloc(1, sizeof(struct tac_acl));
	a->name = strdup(sym->buf);
	a->name_len = l;
	RB_insert(realm->acltable, a);
    }
    sym_get(sym);

    parse(sym, S_openbra);

    struct tac_script_action **p = &a->action;

    while (*p)
	p = &(*p)->n;

    *p = tac_script_parse_r(sym, 1, realm);

    parse(sym, S_closebra);
}

static void attr_add(tac_session * session, char ***v, int *i, char *attr)
{
    if (!*v) {
	*v = memlist_malloc(session->memlist, 0x100 * sizeof(char *));
	*i = 0;
    }
    if (*i < 256)
	(*v)[(*i)++] = memlist_strdup(session->memlist, attr);
}

void cfg_init(void)
{
    init_timespec();
    memset(&config, 0, sizeof(struct config));
    config.mask = 0644;

    {
	struct utsname utsname;
	memset(&utsname, 0, sizeof(struct utsname));
	if (uname(&utsname) || !*(utsname.nodename))
	    config.hostname = "amnesiac";
	else
	    config.hostname = strdup(utsname.nodename);
	config.hostname_len = strlen(config.hostname);
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

int cfg_get_enable(tac_session * session, struct pwdat **p)
{
    if (session->user) {
	int level = session->priv_lvl;
	int level_implied = TAC_PLUS_PRIV_LVL_MAX + 1;

	if (!session->profile && (S_permit != eval_ruleset(session, session->ctx->realm)))
	    return -1;

	if (session->user->enable[level]) {
	    if (!session->user->enable_implied[level]) {
		*p = session->user->enable[level];
		return 0;
	    }
	    if (level_implied > session->user->enable_implied[level]) {
		*p = session->user->enable[level];
		level_implied = session->user->enable_implied[level];
		return 0;
	    }
	}
    }
    if (session->profile) {
	int level = session->priv_lvl;
	int level_implied = TAC_PLUS_PRIV_LVL_MAX + 1;

	if (session->profile->enable[level]) {
	    if (!session->profile->enable_implied[level]) {
		*p = session->profile->enable[level];
		return 0;
	    }
	    if (level_implied > session->profile->enable_implied[level]) {
		*p = session->profile->enable[level];
		level_implied = session->profile->enable_implied[level];
		return 0;
	    }
	}
    }
    {
	int level = session->priv_lvl;
	int level_implied = TAC_PLUS_PRIV_LVL_MAX + 1;

	if (session->ctx->host->enable[level]) {
	    if (!session->ctx->host->enable_implied[level]) {
		*p = session->ctx->host->enable[level];
		return 0;
	    }
	    if (level_implied > session->ctx->host->enable_implied[level]) {
		*p = session->ctx->host->enable[level];
		level_implied = session->ctx->host->enable_implied[level];
		return 0;
	    }
	}
    }
    return -1;
}


struct tac_script_cond_multi {
    int n;
    struct tac_script_cond *e[8];
};

struct tac_script_cond_single {
    enum token a;		// S_context, S_cmd, S_message, S_nac, S_nas, S_nacname, S_port, S_user, S_password
    void *v;			// v2, really
    char *s;			// string
};

struct tac_script_cond {
    enum token type;
    union {
	struct tac_script_cond_single s;
	struct tac_script_cond_multi m;
    } u;
};

static struct tac_script_cond *tac_script_cond_add(struct tac_script_cond *a, struct tac_script_cond *b)
{
    if (a->u.m.n && !(a->u.m.n & 7))
	a = realloc(a, sizeof(struct tac_script_cond) + a->u.m.n * sizeof(struct tac_script_cond *));

    a->u.m.e[a->u.m.n] = b;
    a->u.m.n++;
    return a;
}

static struct tac_script_cond *tac_script_cond_new(enum token type)
{
    struct tac_script_cond *m = calloc(1, sizeof(struct tac_script_cond));
    m->type = type;
    return m;
}

static struct tac_script_cond *tac_script_cond_parse_r(struct sym *sym, tac_realm * realm)
{
    struct tac_script_cond *m, *p = NULL;

    switch (sym->code) {
    case S_leftbra:
	sym_get(sym);
	m = tac_script_cond_add(tac_script_cond_new(S_or), tac_script_cond_parse_r(sym, realm));
	if (sym->code == S_and)
	    m->type = S_and;
	while (sym->code == S_and || sym->code == S_or) {
	    sym_get(sym);
	    m = tac_script_cond_add(m, tac_script_cond_parse_r(sym, realm));
	}
	parse(sym, S_rightbra);
	return m;
    case S_exclmark:
	sym_get(sym);
	m = tac_script_cond_add(tac_script_cond_new(S_exclmark), tac_script_cond_parse_r(sym, realm));
	return m;
    case S_eof:
	parse_error(sym, "EOF unexpected");
    case S_acl:
	m = tac_script_cond_new(S_acl);

	sym_get(sym);
	switch (sym->code) {
	case S_exclmark:
	    p = tac_script_cond_add(tac_script_cond_new(S_exclmark), m);
	case S_equal:
	    break;
	default:
	    parse_error_expect(sym, S_exclmark, S_equal, S_unknown);
	}
	sym_get(sym);

	m->u.s.v = tac_acl_lookup(sym->buf, realm);

	if (!m->u.s.v)
	    parse_error(sym, "ACL '%s' not found", sym->buf);
	sym_get(sym);
	return m;
    case S_time:
	m = tac_script_cond_new(S_time);

	sym_get(sym);
	switch (sym->code) {
	case S_exclmark:
	    p = tac_script_cond_add(tac_script_cond_new(S_exclmark), m);
	case S_equal:
	    break;
	default:
	    parse_error_expect(sym, S_exclmark, S_equal, S_unknown);
	}
	sym_get(sym);

	m->u.s.v = lookup_timespec(sym->buf, realm);
	if (!m->u.s.v)
	    parse_error(sym, "timespec '%s' not found", sym->buf);
	sym_get(sym);
	return m;
    case S_arg:
    case S_cmd:
    case S_context:
    case S_nac:
    case S_nas:
    case S_nasname:
    case S_nacname:
    case S_port:
    case S_user:
    case S_member:
    case S_dn:
    case S_memberof:
    case S_password:
    case S_service:
    case S_protocol:
    case S_authen_action:
    case S_authen_type:
    case S_authen_service:
    case S_authen_method:
    case S_privlvl:
    case S_vrf:
#ifdef WITH_TLS
    case S_tls_conn_version:
    case S_tls_conn_cipher:
    case S_tls_peer_cert_issuer:
    case S_tls_peer_cert_subject:
    case S_tls_conn_cipher_strength:
    case S_tls_peer_cn:
#endif
	m = tac_script_cond_new(S_equal);
	m->u.s.a = sym->code;

	sym_get(sym);
	if (m->u.s.a == S_arg) {
	    parse(sym, S_leftsquarebra);
	    m->u.s.s = strdup(sym->buf);
	    sym_get(sym);
	    parse(sym, S_rightsquarebra);
	}

	switch (sym->code) {
	case S_exclmark:
	    p = tac_script_cond_add(tac_script_cond_new(S_exclmark), m);
	case S_equal:
	    break;
	default:
	    parse_error_expect(sym, S_exclmark, S_equal, S_unknown);
	}
	sym_get(sym);
	switch (sym->code) {
	case S_equal:
	    m->type = S_equal;
	    sym_get(sym);
	    if (m->u.s.a == S_member) {
		tac_group *g = lookup_group(sym->buf, realm);
		if (!g)
		    parse_error(sym, "group %s is not known", sym->buf);
		sym_get(sym);
		m->type = S_member;
		m->u.s.v = g;
		return p ? p : m;
	    }
	    if (m->u.s.a == S_nac || m->u.s.a == S_nas) {
		tac_host *hp;
		tac_net *np;
		if (m->u.s.a == S_nas && (hp = lookup_host(sym->buf, realm))) {
		    m->type = S_host;
		    m->u.s.v = hp;
		} else if (m->u.s.a == S_nas && (np = lookup_net(sym->buf, realm))) {
		    m->type = S_net;
		    m->u.s.v = np;
		} else if (m->u.s.a == S_nac && (np = lookup_net(sym->buf, realm))) {
		    m->type = S_net;
		    m->u.s.v = np;
		} else {
		    struct in6_cidr *c = calloc(1, sizeof(struct in6_cidr));
		    m->u.s.v = c;
		    if (v6_ptoh(&c->addr, &c->mask, sym->buf))
			parse_error(sym, "Expected a net%s name or an IP address/network in CIDR notation, but got '%s'.",
				    (m->u.s.a == S_nas) ? " or host" : "", sym->buf);
		    m->type = S_address;
		}
		sym_get(sym);
		return p ? p : m;
	    }
	    m->u.s.v = strdup(sym->buf);
	    sym_get(sym);
	    return p ? p : m;
	case S_tilde:
	    {			//S_tilde
		int errcode = 0;
		m->type = S_regex;
		sym->flag_parse_pcre = 1;
		sym_get(sym);
		if (sym->code == S_slash) {
#ifdef WITH_PCRE
		    int erroffset;
		    const char *errptr;
		    m->type = S_slash;
		    m->u.s.v = pcre_compile2(sym->buf, PCRE_MULTILINE | common_data.regex_pcre_flags, &errcode, &errptr, &erroffset, NULL);
		    m->u.s.s = strdup(sym->buf);

		    if (!m->u.s.v)
			parse_error(sym, "In PCRE expression /%s/ at offset %d: %s", sym->buf, erroffset, errptr);
		    sym->flag_parse_pcre = 0;
		    sym_get(sym);
		    return p ? p : m;
#else
#ifdef WITH_PCRE2
		    PCRE2_SIZE erroffset;
		    m->type = S_slash;
		    m->u.s.v =
			pcre2_compile((PCRE2_SPTR8) sym->buf, PCRE2_ZERO_TERMINATED, PCRE2_MULTILINE | common_data.regex_pcre_flags, &errcode, &erroffset,
				      NULL);
		    m->u.s.s = strdup(sym->buf);

		    if (!m->u.s.v) {
			PCRE2_UCHAR buffer[256];
			pcre2_get_error_message(errcode, buffer, sizeof(buffer));
			parse_error(sym, "In PCRE2 expression /%s/ at offset %d: %s", sym->buf, erroffset, buffer);
		    }
		    sym->flag_parse_pcre = 0;
		    sym_get(sym);
		    return p ? p : m;
#else
		    parse_error(sym, "You're using PCRE syntax, but this binary wasn't compiled with PCRE support.");
#endif
#endif
		}
		m->u.s.v = calloc(1, sizeof(regex_t));
		errcode = regcomp((regex_t *) m->u.s.v, sym->buf, REG_EXTENDED | REG_NOSUB | REG_NEWLINE | common_data.regex_posix_flags);
		if (errcode) {
		    char e[160];
		    regerror(errcode, (regex_t *) m->u.s.v, e, sizeof(e));
		    parse_error(sym, "In regular expression '%s': %s", sym->buf, e);
		}
		sym_get(sym);
		return p ? p : m;
	    }
	default:
	    parse_error_expect(sym, S_equal, S_tilde, S_unknown);
	}

    default:
	parse_error_expect(sym, S_leftbra, S_exclmark, S_acl, S_time, S_arg, S_cmd, S_context, S_nac, S_nas, S_nasname, S_nacname, S_port, S_user, S_member,
			   S_memberof, S_password, S_service, S_protocol, S_authen_action, S_authen_type, S_authen_service, S_authen_method, S_privlvl, S_vrf, S_dn,
#ifdef WITH_TLS
			   S_tls_conn_version, S_tls_conn_cipher, S_tls_peer_cert_issuer, S_tls_peer_cert_subject, S_tls_conn_cipher_strength, S_tls_peer_cn,
#endif
			   S_unknown);
    }
    return NULL;
}

static void tac_script_cond_optimize(struct tac_script_cond **m)
{
    struct tac_script_cond *p;
    int i;
    while (*m && ((*m)->type == S_or || (*m)->type == S_and) && (*m)->u.m.n == 1) {
	p = *m;
	*m = (*m)->u.m.e[0];
	free(p);
    }
    if (*m)
	for (i = 0; i < (*m)->u.m.n; i++)
	    if ((*m)->type == S_or || (*m)->type == S_and)
		tac_script_cond_optimize(&(*m)->u.m.e[i]);
}

static struct tac_script_cond *tac_script_cond_parse(struct sym *sym, tac_realm * realm)
{
    if (sym->code == S_leftbra) {
	struct sym mysym;
	char buf[4096];
	char *b = buf, *p;
	int bc = 1;
	struct tac_script_cond *m;

	sym_get(sym);

	strcpy(b, "((( ");
	while (*b)
	    b++;

	while (bc && (b < buf + sizeof(buf) - 100)) {
	    switch (sym->code) {
	    case S_and:
		strcpy(b, " ) && (");
		while (*b)
		    b++;
		sym_get(sym);
		continue;
	    case S_or:
		strcpy(b, " )) || ((");
		while (*b)
		    b++;
		sym_get(sym);
		continue;
	    case S_leftbra:
		*b++ = '(';
		bc++;
		break;
	    case S_rightbra:
		*b++ = ')';
		bc--;
		break;
	    case S_openbra:
	    case S_closebra:
		if (bc)
		    parse_error(sym, "Got '%s' -- did you omit a ')' somewhere?", codestring[sym->code]);
		break;
	    case S_tilde:
		sym->flag_parse_pcre = 1;
		break;
	    case S_eof:
		parse_error(sym, "EOF unexpected");
	    default:;
	    }
	    *b++ = ' ';
	    *b = 0;

	    for (p = sym->raw; p < sym->tin - 1; p++)
		*b++ = *p;
	    *b = 0;
	    sym_get(sym);
	    sym->flag_parse_pcre = 0;
	}
	strcpy(b, " )))");
	while (*b)
	    b++;

	memcpy(&mysym, sym, sizeof(mysym));
	mysym.tlen = mysym.len = (int) (b - buf);
	mysym.tin = mysym.in = buf;
	sym_init(&mysym);
	m = tac_script_cond_parse_r(&mysym, realm);
	tac_script_cond_optimize(&m);
	return m;
    }
    return tac_script_cond_parse_r(sym, realm);
}

static int tac_script_cond_eval(tac_session * session, struct tac_script_cond *m)
{
    int i;
    char *v = NULL;
    if (!m)
	return 0;
    switch (m->type) {
    case S_exclmark:
	return !tac_script_cond_eval(session, m->u.m.e[0]);
    case S_and:
	for (i = 0; i < m->u.m.n; i++)
	    if (!tac_script_cond_eval(session, m->u.m.e[i]))
		return 0;
	return -1;
    case S_or:
	for (i = 0; i < m->u.m.n; i++)
	    if (tac_script_cond_eval(session, m->u.m.e[i]))
		return -1;
	return 0;
    case S_address:
	switch (m->u.s.a) {
	case S_nac:
	    if (session->nac_address_valid)
		return v6_contains(&((struct in6_cidr *) (m->u.s.v))->addr, ((struct in6_cidr *) (m->u.s.v))->mask, &session->nac_address);
	    return 0;
	case S_nas:
	    return v6_contains(&((struct in6_cidr *) (m->u.s.v))->addr, ((struct in6_cidr *) (m->u.s.v))->mask, &session->ctx->nas_address);
	default:
	    return 0;
	}

    case S_host:
	{
	    tac_host *h = session->ctx->host;
	    tac_host *hp = h;
	    while (hp) {
		if (h == (tac_host *) (m->u.s.v))
		    return -1;
		hp = hp->parent;
	    }
	    return 0;
	}
    case S_net:
	if (m->u.s.a == S_nas) {
	    tac_net *net = (tac_net *) (m->u.s.v);
	    while (net) {
		if (radix_lookup(net->nettree, &session->ctx->nas_address, NULL))
		    return 1;
		net = net->parent;
	    }
	    return 0;
	}
	if (session->nac_address_valid) {
	    tac_net *net = (tac_net *) (m->u.s.v);
	    while (net) {
		if (radix_lookup(net->nettree, &session->nac_address, NULL))
		    return 1;
		net = net->parent;
	    }
	}
	return 0;
    case S_time:
	return eval_timespec((struct mavis_timespec *) m->u.s.v, NULL);
    case S_member:
	if (session->user)
	    return tac_group_check(m->u.s.v, session->user->groups);
	return 0;
    case S_acl:
	return S_permit == eval_tac_acl(session, (struct tac_acl *) m->u.s.v);
    case S_equal:
    case S_regex:
    case S_slash:
	switch (m->u.s.a) {
	case S_authen_action:
	    v = session->authen_action;
	    break;
	case S_authen_type:
	    v = session->authen_type;
	    break;
	case S_authen_service:
	    v = session->authen_service;
	    break;
	case S_authen_method:
	    v = session->authen_method;
	    break;
	case S_privlvl:
	    v = session->privlvl;
	    break;
	case S_vrf:
	    v = session->ctx->vrf;
	    break;
#ifdef WITH_TLS
	case S_tls_conn_version:
	    v = (char *) session->ctx->tls_conn_version;
	    break;
	case S_tls_conn_cipher:
	    v = (char *) session->ctx->tls_conn_cipher;
	    break;
	case S_tls_peer_cert_issuer:
	    v = (char *) session->ctx->tls_peer_cert_issuer;
	    break;
	case S_tls_peer_cert_subject:
	    v = (char *) session->ctx->tls_peer_cert_subject;
	    break;
	case S_tls_conn_cipher_strength:
	    v = session->ctx->tls_conn_cipher_strength;
	    break;
	case S_tls_peer_cn:
	    v = session->ctx->tls_peer_cn;
	    break;
#endif
	case S_context:
	    v = tac_script_get_exec_context(session, session->username, session->nas_port);
	    break;
	case S_cmd:
	    v = session->cmdline;
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
	case S_port:
	    v = session->nas_port;
	    break;
	case S_user:
	    v = session->username;
	    break;
	case S_password:
	    v = session->password_new ? session->password_new : session->password;
	    break;
	case S_service:
	    v = session->service;
	    break;
	case S_protocol:
	    v = session->protocol;
	    break;
	case S_dn:
	    if (session->user && session->user->avc && session->user->avc->arr[AV_A_DN])
		v = session->protocol;
	    break;
	case S_memberof:
	    if (session->user && session->user->avc && session->user->avc->arr[AV_A_MEMBEROF]) {
		size_t l = strlen(session->user->avc->arr[AV_A_MEMBEROF]) + 1;
		v = alloca(l);
		memcpy(v, session->user->avc->arr[AV_A_MEMBEROF], l);
		while (*v) {
		    char *e;
		    int res;
		    if (*v != '"')
			return 0;
		    v++;
		    for (e = v; *e && *e != '"'; e++);
		    if (*e != '"')
			return 0;
		    *e++ = 0;
		    // perforv checks
		    if (m->type == S_equal) {
			res = !strcasecmp(v, (char *) (m->u.s.v));
			if (res)
			    return res;
		    } else if (m->type == S_slash) {
			res = -1;
#ifdef WITH_PCRE
			res = pcre_exec((pcre *) m->u.s.v, NULL, v, (int) strlen(v), 0, 0, NULL, 0);
			report(session, LOG_DEBUG, DEBUG_REGEX_FLAG, "pcre: '%s' <=> '%s' = %d", m->u.s.s, v, res);
#endif
#ifdef WITH_PCRE2
			pcre2_match_data *match_data = pcre2_match_data_create_from_pattern((pcre2_code *) m->u.s.v, NULL);
			res = pcre2_match((pcre2_code *) m->u.s.v, (PCRE2_SPTR) v, PCRE2_ZERO_TERMINATED, 0, 0, match_data, NULL);
			pcre2_match_data_free(match_data);
			report(session, LOG_DEBUG, DEBUG_REGEX_FLAG, "pcre2: '%s' <=> '%s' = %d", m->u.s.s, v, res);
#endif
			res = -1 < res;
			if (res)
			    return res;
		    } else {
			res = !regexec((regex_t *) m->u.s.v, v, 0, NULL, 0);
			if (res)
			    return res;
		    }
		    v = e;
		    if (!*v || *v != ',')
			return 0;
		    v++;
		}
	    }
	    return 0;
	case S_arg:
	    if (session->argp) {
		u_char arg_cnt = session->arg_cnt;
		u_char *arg_len = session->arg_len;
		u_char *argp = session->argp;
		for (; arg_cnt; arg_cnt--, arg_len++) {
		    size_t len = strlen(m->u.s.s);
		    size_t l;
		    char *s = (char *) argp;
		    l = (size_t) *arg_len;
		    if ((l > len) && !strncmp(s, m->u.s.s, len) && (*(argp + len) == '=' || *(argp + len) == '*')) {
			v = memlist_strndup(session->memlist, argp + len + 1, l - len - 1);
			break;
		    }
		    argp += (size_t) *arg_len;
		}
	    }
	    break;
	default:;
	}
	if (!v)
	    return 0;

	if (m->type == S_equal)
	    return !strcmp(v, (char *) (m->u.s.v));
	if (m->type == S_slash) {
	    int res = -1;
#ifdef WITH_PCRE
	    res = pcre_exec((pcre *) m->u.s.v, NULL, v, (int) strlen(v), 0, 0, NULL, 0);
	    report(session, LOG_DEBUG, DEBUG_REGEX_FLAG, "pcre: '%s' <=> '%s' = %d", m->u.s.s, v, res);
#endif
#ifdef WITH_PCRE2
	    pcre2_match_data *match_data = pcre2_match_data_create_from_pattern((pcre2_code *) m->u.s.v, NULL);
	    res = pcre2_match((pcre2_code *) m->u.s.v, (PCRE2_SPTR) v, PCRE2_ZERO_TERMINATED, 0, 0, match_data, NULL);
	    pcre2_match_data_free(match_data);
	    report(session, LOG_DEBUG, DEBUG_REGEX_FLAG, "pcre2: '%s' <=> '%s' = %d", m->u.s.s, v, res);
#endif
	    return -1 < res;
	}
	return !regexec((regex_t *) m->u.s.v, v, 0, NULL, 0);
    default:;
    }
    return 0;
}

enum token tac_script_eval_r(tac_session * session, struct tac_script_action *m)
{
    enum token r;
    char *v;
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
	session->message = eval_log_format(session, session->ctx, NULL, (struct log_item *) m->b.v, io_now.tv_sec, &session->message_len);
	break;
    case S_rewrite:
	tac_rewrite_user(session, (tac_rewrite *) m->b.v);
	break;
    case S_label:
	session->label = eval_log_format(session, session->ctx, NULL, (struct log_item *) m->b.v, io_now.tv_sec, &session->label_len);
	break;
    case S_profile:
	session->profile = (tac_profile *) (m->b.v);
	break;
    case S_attr:
	session->attr_dflt = (enum token) (long) (m->b.v);
	break;
    case S_add:
    case S_set:
    case S_optional:
	v = eval_log_format(session, session->ctx, NULL, (struct log_item *) m->b.v, io_now.tv_sec, NULL);
	if (m->code == S_set)
	    attr_add(session, &session->attrs_m, &session->cnt_m, v);
	else if (m->code == S_add)
	    attr_add(session, &session->attrs_a, &session->cnt_a, v);
	else			// S_optional
	    attr_add(session, &session->attrs_o, &session->cnt_o, v);
	break;
    case S_if:
	if (tac_script_cond_eval(session, m->a.c)) {
	    r = tac_script_eval_r(session, m->b.a);
	    if (r != S_unknown)
		return r;
	} else if (m->c.a) {
	    r = tac_script_eval_r(session, m->c.a);
	    if (r != S_unknown)
		return r;
	}
	break;
    default:
	return S_unknown;
    }
    return m->n ? tac_script_eval_r(session, m->n) : S_unknown;
}

static struct tac_script_action *tac_script_parse_r(struct sym *sym, int section, tac_realm * realm)
{
    struct tac_script_action *m = NULL;
    char *sep = "=";
    char buf[8192];

    switch (sym->code) {
    case S_closebra:
	return m;
    case S_openbra:
	sym_get(sym);
	m = tac_script_parse_r(sym, 1, realm);
	parse(sym, S_closebra);
	break;
    case S_return:
    case S_permit:
    case S_deny:
	m = calloc(1, sizeof(struct tac_script_action));
	m->code = sym->code;
	sym_get(sym);
	break;
    case S_profile:
	m = calloc(1, sizeof(struct tac_script_action));
	m->code = sym->code;
	sym_get(sym);
	parse(sym, S_equal);
	m->b.v = (char *) lookup_profile(sym->buf, realm);
	sym_get(sym);
	break;
    case S_context:
	m = calloc(1, sizeof(struct tac_script_action));
	m->code = sym->code;
	sym_get(sym);
	parse(sym, S_equal);
	m->b.v = strdup(sym->buf);
	sym_get(sym);
	break;
    case S_message:
	m = calloc(1, sizeof(struct tac_script_action));
	m->code = sym->code;
	sym_get(sym);
	parse(sym, S_equal);
	m->b.v = (char *) parse_log_format(sym);
	break;
    case S_rewrite:
	m = calloc(1, sizeof(struct tac_script_action));
	m->code = sym->code;
	sym_get(sym);
	parse(sym, S_user);
	parse(sym, S_equal);
	m->b.v = (char *) lookup_rewrite(sym->buf, realm);
	sym_get(sym);
	break;
    case S_label:
	m = calloc(1, sizeof(struct tac_script_action));
	m->code = sym->code;
	sym_get(sym);
	parse(sym, S_equal);
	m->b.v = (char *) parse_log_format(sym);
	break;
    case S_attr:
	sym_get(sym);
	parse(sym, S_default);
	m = calloc(1, sizeof(struct tac_script_action));
	m->code = sym->code;
	sym_get(sym);
	parse(sym, S_equal);
	m->b.v = (char *) (keycode(sym->buf));
	sym_get(sym);
	break;
    case S_if:
	m = calloc(1, sizeof(struct tac_script_action));
	m->code = sym->code;
	sym_get(sym);
	m->a.c = tac_script_cond_parse(sym, realm);
	m->b.a = tac_script_parse_r(sym, 0, realm);
	if (sym->code == S_else) {
	    sym_get(sym);
	    m->c.a = tac_script_parse_r(sym, 0, realm);
	}
	break;
    case S_add:
    case S_optional:
	sep = "*";
    case S_set:
	m = calloc(1, sizeof(struct tac_script_action));
	m->code = sym->code;
	sym_get(sym);
	snprintf(buf, sizeof(buf), "\"%s%s\"", sym->buf, sep);
	sym_get(sym);
	m->b.v = (char *) parse_log_format_inline(buf, sym->filename, sym->line);
	parse(sym, S_equal);
	((struct log_item *) m->b.v)->next = parse_log_format(sym);
	break;
    default:
	parse_error_expect(sym, S_openbra, S_closebra, S_return, S_permit, S_deny, S_context, S_message, S_if, S_unknown);
    }
    if (section && sym->code != S_closebra && sym->code != S_eof)
	m->n = tac_script_parse_r(sym, section, realm);
    return m;
}

#ifdef WITH_PCRE2
void tac_rewrite_user(tac_session * session, tac_rewrite * rewrite)
{
    if (!session->username_rewritten) {
	tac_rewrite_expr *e = NULL;
	if (rewrite)
	    e = rewrite->expr;
	if (!e && session->ctx->host->rewrite_user)
	    e = session->ctx->host->rewrite_user->expr;

	if (e) {
	    int rc = -1;
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
		    session->username = memlist_strndup(session->memlist, outbuf, outlen);
		    session->username_len = outlen;
		    session->username_rewritten = 1;
		    report(session, LOG_DEBUG, DEBUG_REGEX_FLAG, "pcre2: setting username to '%s'", session->username);
		}
	    }
	}
    }
}
#endif

static tac_group *lookup_group(char *name, tac_realm * r)
{
    tac_group g, *res;
    g.name = name;

    while (r) {
	if (r->groups_by_name) {
	    if ((res = RB_lookup(r->groups_by_name, &g)))
		return res;
	}
	r = r->parent;
    }
    return 0;
}

mavis_ctx *lookup_mcx(tac_realm * r)
{
    while (r) {
	if (r->mcx)
	    return r->mcx;
	if (r->usertable)
	    return NULL;
	r = r->parent;
    }
    return NULL;
}

/* add name to tree, return id (globally unique) */
static tac_group *tac_group_new(struct sym *sym, char *name, tac_realm * r)
{
    if (!r->groups_by_name)
	r->groups_by_name = RB_tree_new(compare_groups_by_name, NULL);

    rb_node_t *rbn;
    tac_group g, *gp;
    g.name = name;
    rbn = RB_search(r->groups_by_name, &g);
    if (rbn) {
	gp = RB_payload(rbn, tac_group *);
	parse_error(sym, "Group %s already defined at line %u", sym->buf, gp->line);
    }
    gp = calloc(1, sizeof(tac_group));
    gp->name = strdup(name);
    RB_insert(r->groups_by_name, gp);

    return gp;
}

/* add id to groups struct */
static int tac_group_add(tac_group * add, tac_groups * g, memlist_t * memlist)
{
    if (g->count == g->allocated) {
	g->allocated += 32;
	g->groups = (tac_group **) memlist_realloc(memlist, g->groups, g->allocated * sizeof(tac_group));
	if (!g->groupsp)
	    g->groupsp = (tac_group ***) memlist_add(memlist, &g->groups);
    }
    g->groups[g->count] = add;
    g->count++;
    return 0;
}

static int tac_group_check_r(tac_group * g, tac_group * a)
{
    u_int res = 0;
    if (g == a)
	return -1;
    if (a->parent)
	res = tac_group_check_r(g, a->parent);
    return res;
}

static int tac_group_check(tac_group * g, tac_groups * gids)
{
    if (gids) {
	u_int i;
	for (i = 0; i < gids->count; i++) {
	    u_int res = tac_group_check_r(g, gids->groups[i]);
	    if (res)
		return -1;
	}
    }
    return 0;
}

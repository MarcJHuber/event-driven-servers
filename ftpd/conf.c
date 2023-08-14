/*
 * conf.c
 *
 * (C) 2000-2011 Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include "headers.h"

static const char rcsid[]
    __attribute__ ((used)) = "$Id$";

enum {
    ARG_BOOL = 0, ARG_U_INT, ARG_OCT, ARG_U_LONG, ARG_LONG_LONG, ARG_INT,
    ARG_STRING,
    ARG_SU
};

enum ftp_acl_type { T_cidr = 0, T_string, T_regex_posix, T_regex_pcre };

struct in6_cidr {
    struct in6_addr addr;
    int mask;
};

struct acl_element {
    struct acl_element *next;
    char *string;
    enum ftp_acl_type type;
    u_int negate:1;
    u_int caseless:1;
    u_int line:16;
    union {
	enum token token;
	struct in6_cidr *c;
	struct mavis_timespec *t;
	regex_t *r;
#ifdef WITH_PCRE2
	pcre2_code *p;
#endif
    } blob;
};

struct ftp_acl_expr {
    struct acl_element *src;
    struct acl_element *dst;
    struct acl_element *time;
    struct acl_element *user;
    struct acl_element *path;
    struct acl_element *host;
    struct acl_element *arg;
    u_int state_anon:1;
    u_int state_anon_check:1;
    u_int state_real:1;
    u_int state_real_check:1;
    u_int state_secure:1;
    u_int state_secure_check:1;
    u_int state_authen:1;
    u_int state_authen_check:1;
    struct ftp_acl_expr *next;
};

struct ftp_acl {
    struct ftp_acl_expr *expr;
    char name[1];
};

static rb_tree_t *acltable = NULL;

static struct ftp_acl *lookup_acl(struct sym *sym, char *name)
{
    struct ftp_acl *a = NULL;
    if (name) {
	a = alloca(sizeof(struct ftp_acl) + strlen(name));
	strcpy(a->name, name);
	a = (struct ftp_acl *) RB_lookup(acltable, a);
	if (!a && sym)
	    parse_error(sym, "ACL '%s' not found", name);
    }
    return (a);
}


static int acl_add_cmd(char *cmd, int action, struct ftp_acl *acl, int site, int negate, int log)
{
    struct acl_set *a, **as = site ? requests_site_aclset : requests_aclset;
    int i;

    if ((i = get_request_index(site ? requests_site : requests, cmd)) < 0)
	return 0;

    a = Xcalloc(1, sizeof(struct acl_set));
    a->log = log ? 1 : 0;
    a->negate = negate ? 1 : 0;
    a->permit = action ? 1 : 0;
    a->acl = acl;

    if (!as[i])
	as[i] = a;
    else {
	struct acl_set *b;
	for (b = as[i]; b->next; b = b->next);
	b->next = a;
    }

    return -1;
}

static void acl_conf_set_defaults(void);

void acl_finish()
{
    int i;
    struct service_req *cmds = requests;

    for (i = 0; cmds->cmd; i++, cmds++) {
	requests_aclset[i] = Xcalloc(1, sizeof(struct acl_set));
	requests_aclset[i]->acl = lookup_acl(NULL, cmds->acl_default_name);
	requests_aclset[i]->permit = 1;
    }

    for (cmds = requests_site, i = 0; cmds->cmd; i++, cmds++) {
	requests_site_aclset[i] = Xcalloc(1, sizeof(struct acl_set));
	requests_site_aclset[i]->acl = lookup_acl(NULL, cmds->acl_default_name);
	requests_site_aclset[i]->permit = 1;
    }
}

static int match_regex(void *reg, char *txt, enum ftp_acl_type tat)
{
    switch (tat) {
    case T_regex_posix:
	return !regexec((regex_t *) reg, txt, 0, NULL, 0);
#ifdef WITH_PCRE2
    case T_regex_pcre:{
	    int res;
	    pcre2_match_data *match_data = pcre2_match_data_create_from_pattern((pcre2_code *) reg, NULL);
	    res = pcre2_match((pcre2_code *) reg, (PCRE2_SPTR) txt, (PCRE2_SIZE) strlen(txt), 0, 0, match_data, NULL);
	    pcre2_match_data_free(match_data);
	    return -1 < res;
	}
#endif
    default:
	return 0;
    }
}

enum token eval_ftp_acl(struct context *ctx, struct ftp_acl *acl, char *arg, char *path)
{
    if (acl) {
	Debug((DEBUG_ACL, "+ %s(%s)\n", __func__, acl ? acl->name : "???"));
	struct ftp_acl_expr *r;
	enum token res = S_deny;

	for (r = acl->expr; r; r = r->next) {
	    int match = 0;

	    if (r->state_authen_check) {
		if (r->state_authen && (!ctx->real && !ctx->anonymous))
		    continue;
		if (!r->state_authen && (ctx->real || !ctx->anonymous))
		    continue;
	    } else {

		if (r->state_anon_check) {
		    if (r->state_anon && ctx->anonymous)
			continue;
		    if (!r->state_anon && !ctx->anonymous)
			continue;
		}

		if (r->state_real_check) {
		    if (r->state_real && ctx->real)
			continue;
		    if (!r->state_real && !ctx->real)
			continue;
		}
	    }
#ifdef WITH_SSL
	    if (r->state_secure_check) {
		if (r->state_secure && ctx->ssl_c)
		    continue;
		if (!r->state_secure && !ctx->ssl_c)
		    continue;
	    }
#endif

	    match = 0;

	    if (r->src) {
		struct acl_element *e = r->src;

		while (e) {
		    switch (e->type) {
		    case T_cidr:
			match = v6_contains(&e->blob.c->addr, e->blob.c->mask, &ctx->in6_remote);
			break;
		    default:
			;
		    }
		    if (e->negate)
			match = !match;
		    if (match)
			break;
		    e = e->next;
		}
		if (!match)
		    continue;
	    }

	    Debug((DEBUG_ACL, "src acl matched\n"));
	    match = 0;

	    if (r->dst) {
		struct acl_element *e = r->dst;

		while (e) {
		    switch (e->type) {
		    case T_cidr:
			match = v6_contains(&e->blob.c->addr, e->blob.c->mask, &ctx->in6_remote);
			break;
		    default:
			;
		    }
		    if (e->negate)
			match = !match;
		    if (match)
			break;
		    e = e->next;
		}
		if (!match)
		    continue;
	    }

	    Debug((DEBUG_ACL, "dst acl matched\n"));
	    match = 0;

	    if (r->user) {
		struct acl_element *e = r->user;
		if (!ctx->user)
		    return S_unknown;

		while (e) {
		    if (e->type == T_string)
			match = !(e->caseless ? strcasecmp(ctx->user, e->string) : strcmp(ctx->user, e->string));
		    else
			match = match_regex(e->blob.r, ctx->user, e->type);

		    if (e->negate)
			match = !match;
		    if (match)
			break;
		    e = e->next;
		}
		if (!match)
		    continue;
	    }
	    Debug((DEBUG_ACL, "user acl matched\n"));
	    match = 0;

	    if (r->path) {
		struct acl_element *e = r->path;
		if (!path)
		    return S_unknown;
		while (e) {
		    if (e->type == T_string)
			match = !strcmp(path, e->string);
		    else
			match = match_regex(e->blob.r, path, e->type);

		    if (e->negate)
			match = !match;
		    if (match)
			break;
		    e = e->next;
		}
		if (!match)
		    continue;
	    }
	    Debug((DEBUG_ACL, "path acl matched\n"));
	    match = 0;

	    if (r->arg && !arg)
		return S_unknown;
	    if (r->arg) {
		struct acl_element *e = r->arg;
		while (e) {
		    if (e->type == T_string)
			match = !strcmp(arg, e->string);
		    else
			match = match_regex(e->blob.r, arg, e->type);

		    if (e->negate)
			match = !match;
		    if (match)
			break;
		    e = e->next;
		}
		if (!match)
		    continue;
	    }
	    Debug((DEBUG_ACL, "arg acl matched\n"));
	    match = 0;

	    if (r->host) {
		struct acl_element *e = r->host;
		if (!ctx->hostname)
		    return S_unknown;
		while (e) {
		    if (e->type == T_string)
			match = !strcmp(ctx->hostname, e->string);
		    else
			match = match_regex(e->blob.r, ctx->hostname, e->type);

		    if (e->negate)
			match = !match;
		    if (match)
			break;
		    e = e->next;
		}
		if (!match)
		    continue;
	    }
	    Debug((DEBUG_ACL, "user acl matched\n"));
	    match = 0;

	    if (r->time) {
		struct acl_element *e = r->time;

		while (e) {
		    match = eval_timespec((struct mavis_timespec *) (e->blob.t), NULL);
		    if (e->negate)
			match = !match;
		    if (match)
			break;
		    e = e->next;
		}
		if (!match)
		    continue;

		Debug((DEBUG_ACL, "timespec acl matched\n"));
	    }

	    res = S_permit;
	    break;
	}			/* for */

	Debug((DEBUG_ACL, "result: acl matched\n"));

	Debug((DEBUG_ACL, "- %s(%s) = %s\n", __func__, acl ? acl->name : "???", codestring[res]));
	return res;
    }
    return S_permit;
}


static void acl_conf_copy(struct context *);

void acl_calc(struct context *ctx)
{
    int i;
    struct service_req *cmds = requests;
    SET64_ZERO(ctx->requests);
    SET64_ZERO(ctx->requests_dunno);
    SET64_ZERO(ctx->requests_site);
    SET64_ZERO(ctx->requests_site_dunno);
    SET64_ZERO(ctx->requests_log);
    SET64_ZERO(ctx->requests_site_log);

    for (i = 0; cmds->cmd; i++, cmds++)
	switch (eval_ftp_acl(ctx, requests_aclset[i]->acl, NULL, NULL)) {
	case S_permit:
	    if (!requests_aclset[i]->negate || !requests_aclset[i]->permit) {
		SET64_SET(i, ctx->requests);
		if (requests_aclset[i]->log)
		    SET64_SET(i, ctx->requests_log);
	    }
	    break;
	case S_deny:
	    if (requests_aclset[i]->negate && !requests_aclset[i]->permit) {
		SET64_SET(i, ctx->requests);
		if (requests_aclset[i]->log)
		    SET64_SET(i, ctx->requests_log);
	    }
	    break;
	default:
	    {
		SET64_SET(i, ctx->requests);
		SET64_SET(i, ctx->requests_dunno);
		if (requests_aclset[i]->log)
		    SET64_SET(i, ctx->requests_log);
	    }
	}

    cmds = requests_site;
    for (i = 0; cmds->cmd; i++, cmds++)
	switch (eval_ftp_acl(ctx, requests_site_aclset[i]->acl, NULL, NULL)) {
	case S_permit:
	    if (!requests_site_aclset[i]->negate || !requests_site_aclset[i]->permit) {
		SET64_SET(i, ctx->requests_site);
		if (requests_aclset[i]->log)
		    SET64_SET(i, ctx->requests_site_log);
	    }
	    break;
	case S_deny:
	    if (requests_site_aclset[i]->negate && !requests_site_aclset[i]->permit) {
		SET64_SET(i, ctx->requests_site);
		if (requests_aclset[i]->log)
		    SET64_SET(i, ctx->requests_site_log);
	    }
	    break;
	default:
	    {
		SET64_SET(i, ctx->requests_site);
		SET64_SET(i, ctx->requests_site_dunno);
		if (requests_aclset[i]->log)
		    SET64_SET(i, ctx->requests_site_log);
	    }
	}

    acl_conf_copy(ctx);
}

union whatever {
    int i;
    u_int ui;
    u_long ul;
    long long ll;
    char *s;
    sockaddr_union *su;
};

struct acl_conf {
    char *name;
    u_int negate:1;
    struct ftp_acl *acl;
    union whatever value;
    struct acl_conf *next;
};

static struct acl_conf resolve_ids, allow_dotfiles, allow_conv_checksum,
    allow_symlinks, chmod_dirmask, chmod_filemask, readme_once, readme,
    accept_timeout, conn_timeout, idle_timeout_dfl, idle_timeout_min,
    idle_timeout_max, shape_bandwidth, pasv_ports_first, pasv_ports_last,
    authfailures_max, authfailures_bye, ftpuser, ftpgroup, readme_notify,
    banner, greeting, check_uid, check_gid, check_perm, loglevel,
    accept_conn, passive_addr, welcome, welcome_bye, banner_bye, goodbye,
    maintainer, hostname, binary_only, defumask, allow_conv_gzip,
    address_mismatch, ident_query, ascii_size_limit, allow_mode_z, deflate_level_min, deflate_level_max, deflate_level_dfl;

static void acl_conf_set_defaults()
{
    passive_addr.value.su = DEFAULT_PASSIVE_ADDR;
    resolve_ids.value.ui = DEFAULT_RESOLVE_IDS;
    allow_dotfiles.value.ui = DEFAULT_ALLOW_DOTFILES;
    allow_conv_checksum.value.ui = DEFAULT_ALLOW_CHECKSUM;
    allow_conv_gzip.value.ui = DEFAULT_ALLOW_COMPRESSION;
    readme_once.value.ui = DEFAULT_REMEMBER_README;
    readme_notify.value.ui = DEFAULT_NOTIFY_ONLY;
    allow_symlinks.value.ui = DEFAULT_ALLOW_SYMLINKS;
    chmod_dirmask.value.ui = DEFAULT_CHMOD_DIRMASK;
    chmod_filemask.value.ui = DEFAULT_CHMOD_FILEMASK;
    accept_timeout.value.ul = DEFAULT_ACCEPT_TIMEOUT;
    conn_timeout.value.ul = DEFAULT_CONN_TIMEOUT;
    idle_timeout_dfl.value.ul = DEFAULT_IDLE_TIMEOUT;
    idle_timeout_min.value.ul = DEFAULT_IDLE_TIMEOUT_MIN;
    idle_timeout_max.value.ul = DEFAULT_IDLE_TIMEOUT_MAX;
    shape_bandwidth.value.ul = DEFAULT_SHAPE_BANDWIDTH;
    pasv_ports_first.value.i = DEFAULT_PASV_PORTS_FIRST;
    pasv_ports_last.value.i = DEFAULT_PASV_PORTS_LAST;
    authfailures_max.value.i = DEFAULT_AUTHFAILURES_MAX;
    authfailures_bye.value.i = DEFAULT_AUTHFAILURES_BYE;
    readme.value.s = DEFAULT_README;
    welcome.value.s = DEFAULT_WELCOME;
    welcome_bye.value.ui = DEFAULT_WELCOME_BYE;
    ftpuser.value.s = DEFAULT_FTPUSER;
    ftpgroup.value.s = DEFAULT_FTPGROUP;
    banner.value.s = DEFAULT_BANNER;
    banner_bye.value.ui = DEFAULT_BANNER_BYE;
    greeting.value.s = DEFAULT_GREETING;
    check_uid.value.ui = DEFAULT_CHECK_UID;
    check_gid.value.ui = DEFAULT_CHECK_GID;
    check_perm.value.ui = DEFAULT_CHECK_PERM;
    loglevel.value.ui = LOG_NONE;
    ident_query.value.ui = DEFAULT_IDENT_QUERY;
    goodbye.value.s = DEFAULT_GOODBYE;
    maintainer.value.s = DEFAULT_MAINTAINER;
    hostname.value.s = DEFAULT_HOSTNAME;
    binary_only.value.ui = DEFAULT_BINARY_ONLY;
    defumask.value.ui = DEFAULT_UMASK;
    accept_conn.value.ui = 1;
    allow_mode_z.value.ui = 0;
    address_mismatch.value.ui = 0;
    ascii_size_limit.value.ll = -1;
    deflate_level_min.value.i = 0;
    deflate_level_max.value.i = 9;
    deflate_level_dfl.value.i = 6;
}

static union whatever
*acl_conv_eval(struct context *ctx, struct acl_conf *ac, char *arg, char *path)
{
    struct acl_conf *a = NULL;
    if (ac->next)
	ac = ac->next;

    for (a = ac; a; a = a->next) {
	enum token match;
	Debug((DEBUG_ACL, "acl_conv_eval ACL: %s\n", a ? a->name : "unknown!?"));

	match = eval_ftp_acl(ctx, a->acl, arg, path);

	switch (match) {
	case S_permit:
	    if (a->negate)
		match = S_deny;
	    break;
	case S_deny:
	    if (a->negate)
		match = S_permit;
	    break;
	default:
	    continue;
	}
	if (match == S_deny)
	    continue;
	if (match == S_permit) {
	    return &a->value;
	}
    }

    return &ac->value;		// the default
}

__inline__ static sockaddr_union *acl_conv_eval_su(struct context *ctx, struct acl_conf *ac, char *arg, char *path)
{
    union whatever *u = acl_conv_eval(ctx, ac, arg, path);
    return u->su;
}

__inline__ static u_int acl_conv_eval_ui(struct context *ctx, struct acl_conf *ac, char *arg, char *path)
{
    union whatever *u = acl_conv_eval(ctx, ac, arg, path);
    return u->ui;
}

__inline__ static u_long acl_conv_eval_ul(struct context *ctx, struct acl_conf *ac, char *arg, char *path)
{
    union whatever *u = acl_conv_eval(ctx, ac, arg, path);
    return u->ul;
}

__inline__ static u_long acl_conv_eval_ll(struct context *ctx, struct acl_conf *ac, char *arg, char *path)
{
    union whatever *u = acl_conv_eval(ctx, ac, arg, path);
    return (u_long) (u->ll);
}

__inline__ static int acl_conv_eval_i(struct context *ctx, struct acl_conf *ac, char *arg, char *path)
{
    union whatever *u = acl_conv_eval(ctx, ac, arg, path);
    return u->i;
}

__inline__ static char *acl_conv_eval_s(struct context *ctx, struct acl_conf *ac, char *arg, char *path)
{
    union whatever *u = acl_conv_eval(ctx, ac, arg, path);
    return u->s;
}

void acl_conf_readme(struct context *ctx)
{
    ctx->readme_notify = acl_conv_eval_ui(ctx, &readme_notify, NULL, ctx->cwd);
    ctx->readme_once = acl_conv_eval_ui(ctx, &readme_once, NULL, ctx->cwd);
    ctx->readme = acl_conv_eval_s(ctx, &readme, NULL, ctx->cwd);
    ctx->maintainer = acl_conv_eval_s(ctx, &maintainer, NULL, ctx->cwd);
}

int acl_binary_only(struct context *ctx, char *arg, char *path)
{
    return (ctx->use_ascii && acl_conv_eval_ui(ctx, &binary_only, arg, path));
}

int acl_compression(struct context *ctx, char *arg, char *path)
{
    return (ctx->use_ascii || !acl_conv_eval_ui(ctx, &allow_conv_gzip, arg, path));
}

int acl_checksum(struct context *ctx, char *arg, char *path)
{
    return !acl_conv_eval_ui(ctx, &allow_conv_checksum, arg, path);
}

void acl_set_umask(struct context *ctx, char *arg, char *path)
{
    if (!ctx->umask_set)
	ctx->umask = acl_conv_eval_ui(ctx, &defumask, arg, path);
}

#ifdef WITH_ZLIB
void acl_set_deflate_level(struct context *ctx)
{
    ctx->allow_mode_z = acl_conv_eval_ui(ctx, &allow_mode_z, NULL, ctx->filename[0] ? ctx->filename : NULL);

    if (ctx->allow_mode_z) {
	ctx->deflate_level_min = acl_conv_eval_i(ctx, &deflate_level_min, NULL, ctx->filename[0] ? ctx->filename : NULL);
	if (ctx->deflate_level_min < 0)
	    ctx->deflate_level_min = 0;
	ctx->deflate_level_max = acl_conv_eval_i(ctx, &deflate_level_max, NULL, ctx->filename[0] ? ctx->filename : NULL);
	if (ctx->deflate_level_max > 9)
	    ctx->deflate_level_max = 9;
	ctx->deflate_level_dfl = acl_conv_eval_i(ctx, &deflate_level_dfl, NULL, ctx->filename[0] ? ctx->filename : NULL);
	if (ctx->deflate_level_dfl < ctx->deflate_level_min)
	    ctx->deflate_level_dfl = ctx->deflate_level_min;
	if (ctx->deflate_level_dfl > ctx->deflate_level_max)
	    ctx->deflate_level_dfl = ctx->deflate_level_max;

	ctx->deflate_level = ctx->deflate_level_dfl;
	Debug((DEBUG_PROC, "deflate_level = %d (%d...%d...%d)\n",
	       ctx->deflate_level, ctx->deflate_level_min, ctx->deflate_level_dfl, ctx->deflate_level_max));
    }
}
#endif

static void acl_conf_copy(struct context *ctx)
{
    acl_conf_readme(ctx);
    acl_set_umask(ctx, NULL, NULL);
    ctx->passive_addr = acl_conv_eval_su(ctx, &passive_addr, NULL, NULL);
    ctx->resolve_ids = acl_conv_eval_ui(ctx, &resolve_ids, NULL, NULL);
    ctx->allow_dotfiles = acl_conv_eval_ui(ctx, &allow_dotfiles, NULL, NULL);
    ctx->allow_symlinks = acl_conv_eval_ui(ctx, &allow_symlinks, NULL, NULL);
    ctx->chmod_dirmask = acl_conv_eval_ui(ctx, &chmod_dirmask, NULL, NULL);
    ctx->chmod_filemask = acl_conv_eval_ui(ctx, &chmod_filemask, NULL, NULL);
    ctx->accept_timeout = acl_conv_eval_ul(ctx, &accept_timeout, NULL, NULL);
    ctx->conn_timeout = acl_conv_eval_ul(ctx, &conn_timeout, NULL, NULL);

    if (ctx->idle_timeout)
	io_sched_del(ctx->io, ctx, (void *) cleanup);
    ctx->idle_timeout = ctx->idle_timeout_dfl = acl_conv_eval_ul(ctx, &idle_timeout_dfl, NULL, NULL);
    if (ctx->idle_timeout)
	io_sched_add(ctx->io, ctx, (void *) cleanup, ctx->idle_timeout, 0);

    ctx->idle_timeout_min = acl_conv_eval_ul(ctx, &idle_timeout_min, NULL, NULL);
    ctx->idle_timeout_max = acl_conv_eval_ul(ctx, &idle_timeout_max, NULL, NULL);
    ctx->shape_bandwidth = acl_conv_eval_ul(ctx, &shape_bandwidth, NULL, NULL);
    ctx->pasv_ports_first = acl_conv_eval_i(ctx, &pasv_ports_first, NULL, NULL);
    ctx->pasv_ports_last = acl_conv_eval_i(ctx, &pasv_ports_last, NULL, NULL);
    ctx->authfailures_max = acl_conv_eval_i(ctx, &authfailures_max, NULL, NULL);
    ctx->authfailures_bye = acl_conv_eval_i(ctx, &authfailures_bye, NULL, NULL);
    ctx->welcome = acl_conv_eval_s(ctx, &welcome, NULL, NULL);
    ctx->welcome_bye = acl_conv_eval_ui(ctx, &welcome_bye, NULL, NULL);
    ctx->banner_bye = acl_conv_eval_ui(ctx, &banner_bye, NULL, NULL);
    ctx->ftpuser = acl_conv_eval_s(ctx, &ftpuser, NULL, NULL);
    ctx->ftpgroup = acl_conv_eval_s(ctx, &ftpgroup, NULL, NULL);
    ctx->banner = acl_conv_eval_s(ctx, &banner, NULL, NULL);
    if (!(ctx->greeting = acl_conv_eval_s(ctx, &greeting, NULL, NULL)))
	ctx->greeting = DEFAULT_GREETING;

    ctx->loglevel = acl_conv_eval_ul(ctx, &loglevel, NULL, NULL);
    ctx->accept = acl_conv_eval_ui(ctx, &accept_conn, NULL, NULL);
    ctx->goodbye = acl_conv_eval_s(ctx, &goodbye, NULL, NULL);
    ctx->hostname = acl_conv_eval_s(ctx, &hostname, NULL, NULL);
    ctx->address_mismatch = acl_conv_eval_ui(ctx, &address_mismatch, NULL, NULL);
    ctx->ident_query = acl_conv_eval_ui(ctx, &ident_query, NULL, NULL);
    ctx->ascii_size_limit = acl_conv_eval_ll(ctx, &ascii_size_limit, NULL, NULL);
#ifdef WITH_ZLIB
    acl_set_deflate_level(ctx);
#endif
}

static int add_var_acl(struct sym *sym, struct acl_conf *a, char *name, int type, char *value, int negate)
{
    if (value) {
	struct acl_conf **r = &a;
	char multiplicator;
	while (*r)
	    r = &(*(r))->next;
	*r = Xcalloc(1, sizeof(struct acl_conf));
	(*r)->negate = negate;
	(*r)->name = name ? Xstrdup(name) : ACL_LOGIN;
	(*r)->acl = lookup_acl(sym, (*r)->name);
	switch (type) {
	case ARG_BOOL:
	    (*r)->value.ui = value[0] ? 1 : 0;
	    break;
	case ARG_U_INT:
	    sscanf(value, "%u", &(*r)->value.ui);
	    break;
	case ARG_OCT:
	    sscanf(value, "%o", &(*r)->value.ui);
	    break;
	case ARG_U_LONG:
	    if (2 == sscanf(value, "%lu%c", &(*r)->value.ul, &multiplicator)) {
		switch (multiplicator) {
		case 'm':
		case 'M':
		    (*r)->value.ul <<= 10;
		case 'k':
		case 'K':
		    (*r)->value.ul <<= 10;
		    break;
		}
	    }
	    break;
	case ARG_LONG_LONG:
	    if (2 == sscanf(value, "%lld%c", &(*r)->value.ll, &multiplicator)) {
		switch (multiplicator) {
		case 'm':
		case 'M':
		    (*r)->value.ll <<= 10;
		case 'k':
		case 'K':
		    (*r)->value.ll <<= 10;
		    break;
		}
	    }
	    break;
	case ARG_INT:
	    sscanf(value, "%d", &(*r)->value.i);
	    break;
	case ARG_STRING:
	    (*r)->value.s = Xstrdup(value);
	    break;
	case ARG_SU:
	    (*r)->value.s = value;
	}
    }
    return -1;
}

static int compare_acl(const void *a, const void *b)
{
    return strcmp(((struct ftp_acl *) a)->name, ((struct ftp_acl *) b)->name);
}

static rb_tree_t *timespectable = NULL;

void cfg_init(void)
{
    int i;
    char *t;
    struct service_req *cmds = requests;
    struct sym sym;

    timespectable = init_timespec();

    acltable = RB_tree_new(compare_acl, NULL);

    t = "acl = secure { protected = yes } "
	"acl = any { } "
	"acl = connect { } " "acl = real { authenticated = real } " "acl = anon { authenticated = anon } " "acl = login { authenticated = yes }";

    memset(&sym, 0, sizeof(sym));
    sym.in = sym.tin = t;
    sym.tlen = sym.len = strlen(t);
    sym_init(&sym);
    parse_decls(&sym);
    acl_conf_set_defaults();
    for (i = 0; cmds->cmd; i++, cmds++);
    requests_aclset = Xcalloc(i, sizeof(struct acl_set *));
    for (cmds = requests_site, i = 0; cmds->cmd; i++, cmds++);
    requests_site_aclset = Xcalloc(i, sizeof(struct acl_set *));
}

static void parse_aclconf(struct sym *sym, int type, struct acl_conf *ac, char *dacl)
{
    char *acl = NULL;
    int negate = 0;
    if (!dacl)
	dacl = ACL_CONNECT;
    sym_get(sym);
    switch (sym->code) {
    case S_acl:
	sym_get(sym);
	if (sym->code == S_not) {
	    negate = 1;
	    sym_get(sym);
	}
	strset(&acl, sym->buf);
	sym_get(sym);
    case S_equal:
	parse(sym, S_equal);
	if (type == ARG_BOOL)
	    add_var_acl(sym, ac, acl ? acl : dacl, ARG_BOOL, parse_bool(sym) ? "1" : "", negate);
	else {
	    add_var_acl(sym, ac, acl ? acl : dacl, ARG_STRING, sym->buf, negate);
	    sym_get(sym);
	}
	Xfree(&acl);
	break;
    default:
	parse_error_expect(sym, S_acl, S_equal, S_unknown);
    }
}

static void parse_aclconf_logout(struct sym *sym, struct acl_conf *ac, char *dacl)
{
    char *acl = NULL;
    int negate = 0;
    sym_get(sym);
    switch (sym->code) {
    case S_acl:
	sym_get(sym);
	if (sym->code == S_not) {
	    negate = 1;
	    sym_get(sym);
	}
	strset(&acl, sym->buf);
	sym_get(sym);
    case S_equal:
	parse(sym, S_equal);
	parse(sym, S_logout);
	add_var_acl(sym, ac, acl ? acl : dacl, ARG_STRING, "1", negate);
	Xfree(&acl);
	break;
    default:
	parse_error_expect(sym, S_acl, S_equal, S_unknown);
    }
}


static enum ftp_acl_type parse_aclregex(struct sym *sym, struct acl_element *ae, int ic)
{
    int errcode = 0;
    if (sym->code == S_slash) {
#ifdef WITH_PCRE2
	PCRE2_SIZE erroffset;
	ae->blob.p =
	    pcre2_compile((PCRE2_SPTR8) sym->buf, PCRE2_ZERO_TERMINATED, PCRE2_MULTILINE | PCRE2_UTF | (ic ? PCRE2_CASELESS : 0), &errcode, &erroffset, NULL);
	if (!ae->blob.p) {
	    PCRE2_UCHAR buffer[256];
	    pcre2_get_error_message(errcode, buffer, sizeof(buffer));
	    parse_error(sym, "In PCRE2 expression /%s/ at offset %d: %s", sym->buf, erroffset, buffer);
	}
	sym_get(sym);
	return T_regex_pcre;
#else
	parse_error(sym, "You're using PCRE2 syntax, but this binary wasn't compiled with PCRE2 support.");
#endif
    }
    ae->blob.r = calloc(1, sizeof(regex_t));
    errcode = regcomp(ae->blob.r, sym->buf, REG_EXTENDED | REG_NOSUB | REG_NEWLINE | (ic ? REG_ICASE : 0));
    if (errcode) {
	char e[160];
	regerror(errcode, ae->blob.r, e, sizeof(e));
	parse_error(sym, "In regular expression '%s': %s", sym->buf, e);
    }
    sym_get(sym);
    return T_regex_posix;
}


static void parse_ftp_acl_expr(struct sym *sym, struct ftp_acl_expr **e)
{
    struct acl_element **r;

    if (!*e)
	*e = calloc(1, sizeof(struct ftp_acl_expr));

#if 0
    acl = <name > {
    acl_expr +}
    state =[not] (connect | login | anonymous | real | secure)
	(src | dst) =[not] < cidr >
	arg[regex[ignore - case]] =[not] < string >
	path[regex[ignore - case]] =[not] < string >
	user[regex[ignore - case]] =[not] < string > host[regex[ignore - case]] =[not] < string > time =[not] < timespecname >
#endif
	while (1) {
	switch (sym->code) {
	case S_eof:
	    parse_error(sym, "EOF unexpected");
	case S_closebra:
	    return;
	case S_src:
	case S_dst:
	    // src = [not] <cidr>
	    // dst = [not] <cidr>
	    r = (sym->code == S_src) ? &(*e)->src : &(*e)->dst;
	    sym_get(sym);
	    while (*r)
		r = &(*r)->next;
	    *r = calloc(1, sizeof(struct acl_element));
	    (*r)->line = sym->line;
	    parse(sym, S_equal);
	    if (sym->code == S_not) {
		(*r)->negate = 1;
		sym_get(sym);
	    }
	    (*r)->blob.c = calloc(1, sizeof(struct in6_cidr));
	    if (v6_ptoh(&(*r)->blob.c->addr, &(*r)->blob.c->mask, sym->buf))
		parse_error(sym, "Expected a hostname or an IP " "address/network in CIDR notation, " "but got '%s'.", sym->buf);
	    (*r)->type = T_cidr;
	    (*r)->string = strdup(sym->buf);
	    sym_get(sym);
	    break;

	case S_arg:
	case S_path:
	case S_user:
	case S_host:
	    switch (sym->code) {
	    case S_arg:
		r = &(*e)->arg;
		break;
	    case S_path:
		r = &(*e)->path;
		break;
	    case S_user:
		r = &(*e)->user;
		break;
	    default:
		r = &(*e)->host;
	    }
	    sym->flag_parse_pcre = 1;
	    sym_get(sym);
	    while (*r)
		r = &(*r)->next;
	    *r = calloc(1, sizeof(struct acl_element));
	    (*r)->line = sym->line;
	    parse(sym, S_equal);
	    if (sym->code == S_not) {
		(*r)->negate = 1;
		sym_get(sym);
	    }
	    if (sym->code == S_regex) {
		sym_get(sym);
		if (sym->code == S_caseless) {
		    (*r)->caseless = 1;
		    sym_get(sym);
		}
		(*r)->string = strdup(sym->buf);
		(*r)->type = parse_aclregex(sym, *r, (*r)->caseless);
	    } else {
		if (sym->code == S_caseless) {
		    (*r)->caseless = 1;
		    sym_get(sym);
		}
		(*r)->string = strdup(sym->buf);
		(*r)->type = T_string;
	    }
	    sym->flag_parse_pcre = 0;
	    break;
	case S_time:{
		struct mavis_timespec *ts;
		sym_get(sym);
		r = &(*e)->time;
		while (*r)
		    r = &(*r)->next;
		*r = calloc(1, sizeof(struct acl_element));
		(*r)->line = sym->line;
		parse(sym, S_equal);
		if (sym->code == S_not) {
		    (*r)->negate = 1;
		    sym_get(sym);
		}
		ts = find_timespec(timespectable, sym->buf);
		if (!ts)
		    parse_error(sym, "timespec '%s' not found", sym->buf);
		(*r)->blob.t = ts;
		sym_get(sym);
		break;
	    }
	case S_authenticated:
	    sym_get(sym);
	    parse(sym, S_equal);
	    switch (sym->code) {
	    case S_anon:
		(*e)->state_anon = 1;
		(*e)->state_anon_check = 1;
		break;
	    case S_permit:
	    case S_yes:
		(*e)->state_authen_check = 1;
		(*e)->state_authen = 1;
		break;
	    case S_real:
		(*e)->state_real = 1;
		(*e)->state_real_check = 1;
		break;
	    case S_deny:
	    case S_no:
		(*e)->state_authen_check = 1;
		(*e)->state_authen = 0;
		break;
	    default:
		parse_error_expect(sym, S_anon, S_real, S_yes, S_no, S_unknown);
	    }
	    sym_get(sym);
	    break;
	case S_protected:
	    sym_get(sym);
	    parse(sym, S_equal);
	    switch (sym->code) {
	    case S_permit:
	    case S_yes:
		(*e)->state_secure = 1;
		(*e)->state_secure_check = 1;
		break;
	    case S_deny:
	    case S_no:
		(*e)->state_secure = 0;
		(*e)->state_secure_check = 1;
		break;
	    default:
		parse_error_expect(sym, S_yes, S_no, S_unknown);
	    }
	    sym_get(sym);
	    break;
	default:
	    parse_error_expect(sym, S_src, S_dst, S_arg, S_path, S_user, S_host, S_time, S_authenticated, S_protected, S_unknown);
	}
    }
}



static void parse_ftp_acl(struct sym *sym)
{
    struct ftp_acl *a;
    struct ftp_acl_expr **e;
    sym_get(sym);
    parse(sym, S_equal);
    a = lookup_acl(NULL, sym->buf);
    if (!a) {
	a = calloc(1, sizeof(struct ftp_acl) + strlen(sym->buf));
	strcpy(a->name, sym->buf);
	RB_insert(acltable, a);
    }
    sym_get(sym);
    e = &a->expr;
    while (*e)
	e = &((*e)->next);
    parse(sym, S_openbra);
    parse_ftp_acl_expr(sym, e);
    parse(sym, S_closebra);
    return;
}


void parse_decls(struct sym *sym)
{
    /* Top level of parser */
    while (1)
	switch (sym->code) {
	case S_closebra:
	case S_eof:
	    return;
	    case_CC_Tokens;
	case S_ident:
	    // ident [ acl [not] <aclname> ] = (permit|deny)
	    parse_aclconf(sym, ARG_BOOL, &ident_query, ACL_CONNECT);
	    continue;
	case S_greeting:
	    // greeting [ acl [not] <aclname> ] = <string>
	    parse_aclconf(sym, ARG_STRING, &greeting, ACL_CONNECT);
	    continue;
	case S_banner:
	    // banner [ acl [not] <aclname> ] = <string>
	    parse_aclconf(sym, ARG_STRING, &banner, ACL_CONNECT);
	    continue;
	case S_welcome:
	    // welcome [ acl [not] <aclname> ] = <string>
	    parse_aclconf(sym, ARG_STRING, &welcome, NULL);
	    continue;
	case S_welcomeaction:
	    // welcome-action [ acl [not] <aclname> ] = logout
	    parse_aclconf_logout(sym, &welcome_bye, NULL);
	    continue;
	case S_banneraction:
	    // banner-action [ acl [not] <aclname> ] = logout
	    parse_aclconf_logout(sym, &banner_bye, ACL_CONNECT);
	    continue;
	case S_goodbye:
	    // goodbye [ acl [not] <aclname> ] = <string>
	    parse_aclconf(sym, ARG_STRING, &welcome, NULL);
	    continue;
	case S_maintainer:
	    // maintainer [ acl [not] <aclname> ] = <string>
	    parse_aclconf(sym, ARG_STRING, &maintainer, ACL_CONNECT);
	    continue;
	case S_hostname:
	    // hostname [ acl [not] <aclname> ] = <string>
	    parse_aclconf(sym, ARG_STRING, &hostname, ACL_CONNECT);
	    continue;
	case S_readme:
	    // readme [ acl [not] <aclname> ] = <string>
	    parse_aclconf(sym, ARG_STRING, &readme, NULL);
	    continue;
	case S_readmeonce:
	    //readme-once [ acl [not] <aclname> ] = (permit|deny)
	    parse_aclconf(sym, ARG_BOOL, &readme_once, NULL);
	    continue;
	case S_readmenotify:
	    //readme-notify [ acl [not] <aclname> ] = (permit|deny)
	    parse_aclconf(sym, ARG_BOOL, &readme_notify, NULL);
	    continue;
	case S_fakeowner:
	    // fake-owner [ acl [not] <aclname> ] = <string>
	    parse_aclconf(sym, ARG_STRING, &ftpuser, NULL);
	    continue;
	case S_fakegroup:
	    // fake-group [ acl [not] <aclname> ] = <string>
	    parse_aclconf(sym, ARG_STRING, &ftpgroup, NULL);
	    continue;
	case S_resolveids:
	    // resolve-ids [ acl [not] <aclname> ] = (permit|deny)
	    parse_aclconf(sym, ARG_BOOL, &resolve_ids, NULL);
	    continue;
	case S_allowdotfiles:
	    // dotfiles [ acl [not] <aclname> ] = (permit|deny)
	    parse_aclconf(sym, ARG_BOOL, &allow_dotfiles, NULL);
	    continue;
	case S_authenticationfailures:
	    // authentication-failures (max|bye) [ acl [not] <aclname> ] = <n>
	    sym_get(sym);
	    switch (sym->code) {
	    case S_max:
		parse_aclconf(sym, ARG_INT, &authfailures_max, NULL);
		continue;
	    case S_bye:
		parse_aclconf(sym, ARG_INT, &authfailures_bye, NULL);
		continue;
	    default:
		parse_error_expect(sym, S_bye, S_max, S_unknown);
	    }
	case S_asciisizelimit:
	    //ascii-size-limit [ acl [not] <aclname> ] = <longlong>
	    parse_aclconf(sym, ARG_LONG_LONG, &ascii_size_limit, ACL_CONNECT);
	    continue;
	case S_checkuid:
	    //check-uid [ acl [not] <aclname> ] = (permit|deny)
	    parse_aclconf(sym, ARG_BOOL, &check_uid, NULL);
	    continue;
	case S_checkgid:
	    //check-gid [ acl [not] <aclname> ] = (permit|deny)
	    parse_aclconf(sym, ARG_BOOL, &check_gid, NULL);
	    continue;
	case S_checkperm:
	    //check-perm [ acl [not] <aclname> ] = (permit|deny)
	    parse_aclconf(sym, ARG_BOOL, &check_perm, NULL);
	    continue;
	case S_mavis:
	    sym_get(sym);
	    switch (sym->code) {
	    case S_module:
		if (parse_mavismodule(&mcx, io, sym))
		    scm_fatal();
		continue;
	    case S_path:
		parse_mavispath(sym);
		continue;
	    default:
		parse_error_expect(sym, S_module, S_path, S_unknown);
	    }
	case S_idle:
	    //idle timeout (min|max|default) [ acl [not] <aclname> ] = ...
	    sym_get(sym);
	    parse(sym, S_timeout);
	    switch (sym->code) {
	    case S_default:
		parse_aclconf(sym, ARG_INT, &idle_timeout_dfl, ACL_CONNECT);
		continue;
	    case S_min:
		parse_aclconf(sym, ARG_INT, &idle_timeout_min, ACL_CONNECT);
		continue;
	    case S_max:
		parse_aclconf(sym, ARG_INT, &idle_timeout_max, ACL_CONNECT);
		continue;
	    default:
		parse_error_expect(sym, S_min, S_max, S_default, S_unknown);
	    }
	    continue;
	case S_connection:
	    //connection timeout [ acl [not] <aclname> ] = ...
	    sym_get(sym);
	    if (sym->code != S_timeout)
		parse_error_expect(sym, S_timeout, S_unknown);
	    parse_aclconf(sym, ARG_INT, &conn_timeout, ACL_CONNECT);
	    continue;
	case S_accept:
	    //accept timeout [ acl [not] <aclname> ] = ...
	    sym_get(sym);
	    if (sym->code != S_timeout)
		parse_error_expect(sym, S_timeout, S_unknown);
	    parse_aclconf(sym, ARG_INT, &accept_timeout, ACL_CONNECT);
	    continue;
	case S_chmodmask:
	    //chmod-mask (file|directory) [ acl [not] <aclname> ] = ...
	    sym_get(sym);
	    switch (sym->code) {
	    case S_file:
		parse_aclconf(sym, ARG_OCT, &chmod_filemask, ACL_LOGIN);
		continue;
	    case S_directory:
		parse_aclconf(sym, ARG_OCT, &chmod_dirmask, ACL_LOGIN);
		continue;
	    default:
		parse_error_expect(sym, S_file, S_directory, S_unknown);
	    }
	case S_access:
	    //access [ acl [not] <aclname> ] = (permit|deny)
	    parse_aclconf(sym, ARG_BOOL, &accept_conn, ACL_CONNECT);
	    continue;
	case S_addressmismatch:
	    //address-mismatch [ acl [not] <aclname> ] = (permit|deny)
	    parse_aclconf(sym, ARG_BOOL, &address_mismatch, ACL_CONNECT);
	    continue;
	case S_nlst:
	    //nlst = files-only
	    sym_get(sym);
	    parse(sym, S_equal);
	    parse(sym, S_filesonly);
	    nlst_files_only = -1;
	    continue;
	case S_hideversion:
	    // hide-version = (permit|deny)
	    sym_get(sym);
	    parse(sym, S_equal);
	    hide_version = parse_bool(sym);
	    continue;
	case S_shapebandwidth:
	    // shape-bandwidth [ acl [not] <aclname> ] = ...
	    parse_aclconf(sym, ARG_U_LONG, &shape_bandwidth, NULL);
	    continue;
	case S_symlinks:{
		char *acl = NULL;
		char n[20];
		int res = SYMLINKS_NO;
		int loop = 1;
		int negate = 0;
		sym_get(sym);
		switch (sym->code) {
		case S_acl:
		    sym_get(sym);
		    if (sym->code == S_not) {
			negate = 1;
			sym_get(sym);
		    }
		    strset(&acl, sym->buf);
		    sym_get(sym);
		case S_equal:
		    parse(sym, S_equal);
		    while (loop) {
			switch (sym->code) {
			case S_all:
			    res = SYMLINKS_YES;
			    break;
			case S_none:
			    res = SYMLINKS_NO;
			    break;
			case S_root:
			    res |= SYMLINKS_ROOT;
			    break;
			case S_same:
			    res |= SYMLINKS_SAME;
			    break;
			case S_real:
			    res |= SYMLINKS_REAL;
			    break;
			default:
			    loop = 0;
			}
			if (loop)
			    sym_get(sym);
		    }
		    snprintf(n, sizeof(n), "%d", res);
		    add_var_acl(sym, &allow_symlinks, acl, ARG_INT, n, negate);
		    Xfree(&acl);
		    break;
		default:
		    parse_error_expect(sym, S_acl, S_equal, S_unknown);
		}
		continue;
	    }
	case S_log:{
		char *acl = NULL;
		int negate = 0;
		char n[20];
		int res = LOG_NONE;
		int loop = 1;
		sym_get(sym);
		switch (sym->code) {
		case S_acl:
		    sym_get(sym);
		    if (sym->code == S_not) {
			negate = 1;
			sym_get(sym);
		    }
		    strset(&acl, sym->buf);
		    sym_get(sym);
		case S_equal:
		    parse(sym, S_equal);
		    while (loop) {
			switch (sym->code) {
			case S_none:
			    res = LOG_NONE;
			    break;
			case S_cmd:
			case S_command:
			    res |= LOG_COMMAND;
			    break;
			case S_transfer:
			    res |= LOG_TRANSFER;
			    break;
			case S_event:
			    res |= LOG_EVENT;
			    break;
			case S_ident:
			    res |= LOG_IDENT;
			    break;
			default:
			    loop = 0;
			}
			if (loop)
			    sym_get(sym);
		    }
		    snprintf(n, sizeof(n), "%d", res);
		    add_var_acl(sym, &loglevel, acl ? acl : ACL_CONNECT, ARG_U_LONG, n, negate);
		    Xfree(&acl);
		    break;
		default:
		    parse_error_expect(sym, S_acl, S_equal, S_unknown);
		}
		continue;
	    }
	case S_umask:
	    // umask [ acl [not] <aclname> ] = ...
	    parse_aclconf(sym, ARG_OCT, &defumask, ACL_LOGIN);
	    continue;
	case S_binaryonly:
	    // binary-only [ acl [not] <aclname> ] = (yes|no)
	    parse_aclconf(sym, ARG_BOOL, &binary_only, NULL);
	    continue;
	case S_mimetypes:
	    sym_get(sym);
	    parse(sym, S_equal);
	    read_mimetypes(sym->buf);
	    sym_get(sym);
	    continue;
#ifdef WITH_MMAP
	case S_usemmap:
	    //use-mmap = (yes|no)
	    sym_get(sym);
	    parse(sym, S_equal);
	    use_mmap = parse_bool(sym);
	    continue;
#endif				/* WITH_MMAP */
#ifdef WITH_SENDFILE
	case S_usesendfile:
	    //use-sendfile = (yes|no)
	    sym_get(sym);
	    parse(sym, S_equal);
	    use_sendfile = parse_bool(sym);
	    continue;
#endif				/* WITH_MMAP */
	case S_buffer:{
		// buffer (size|mmap-size) = ...
		char c;
		int b;
		sym_get(sym);
		switch (sym->code) {
		case S_size:
		    sym_get(sym);
		    parse(sym, S_equal);

		    if (2 == sscanf(sym->buf, "%d%c", &b, &c)) {
			bufsize = (size_t) b;
			switch (c) {
			case 'k':
			case 'K':
			    bufsize <<= 10;
			    break;
			case 'm':
			case 'M':
			    bufsize <<= 20;
			    break;
			}
			sym_get(sym);
		    } else
			bufsize = parse_int(sym);
		    break;
#ifdef WITH_MMAP
		case S_mmapsize:
		    sym_get(sym);
		    parse(sym, S_equal);

		    if (2 == sscanf(sym->buf, "%d%c", &b, &c)) {
			bufsize_mmap = (size_t) b;
			switch (c) {
			case 'k':
			case 'K':
			    bufsize_mmap <<= 10;
			    break;
			case 'm':
			case 'M':
			    bufsize_mmap <<= 20;
			    break;
			}
			sym_get(sym);
		    } else
			bufsize_mmap = parse_int(sym);
		    break;
#endif				/* WITH_MMAP */
		default:
		    parse_error_expect(sym, S_size,
#ifdef WITH_MMAP
				       S_mmapsize,
#endif
				       S_unknown);
		}
		continue;
	    }
	case S_retire:
	    sym_get(sym);
	    parse(sym, S_limit);
	    parse(sym, S_equal);
	    id_max = (u_long) parse_int(sym);
	    continue;

	case S_transmissionmode:
	    //transmission-mode z [ acl [not] <aclname> ] = (yes|no)
	    sym_get(sym);
	    if (sym->code != S_z)
		parse_error_expect(sym, S_z, S_unknown);
	    parse_aclconf(sym, ARG_BOOL, &allow_mode_z, NULL);
	    continue;
	case S_deflatelevel:
	    //deflate-level (min|max|default) [ acl [not] <aclname> ] = ...
	    sym_get(sym);
	    switch (sym->code) {
	    case S_default:
		parse_aclconf(sym, ARG_INT, &deflate_level_dfl, NULL);
		continue;
	    case S_min:
		parse_aclconf(sym, ARG_INT, &deflate_level_min, NULL);
		continue;
	    case S_max:
		parse_aclconf(sym, ARG_INT, &deflate_level_max, NULL);
		continue;
	    default:
		parse_error_expect(sym, S_min, S_max, S_default, S_unknown);
	    }
	    continue;
	case S_autoconversion:
	    // auto-conversion (gzip|deflate|checksum) [ acl [not] <aclname> ] = (permit|deny)
	    sym_get(sym);
	    switch (sym->code) {
	    case S_deflate:
	    case S_gzip:
		parse_aclconf(sym, ARG_BOOL, &allow_conv_gzip, NULL);
		continue;
	    case S_checksum:
		parse_aclconf(sym, ARG_BOOL, &allow_conv_checksum, NULL);
		continue;
	    default:
		parse_error_expect(sym, S_checksum, S_deflate, S_gzip, S_unknown);
	    }

	case S_passive:
	    // passive port (min|max) = ...
	    sym_get(sym);
	    switch (sym->code) {
	    case S_address:{
		    char *acl = NULL;
		    int negate = 0;
		    sockaddr_union *su = Xcalloc(1, sizeof(sockaddr_union));

		    sym_get(sym);
		    switch (sym->code) {
		    case S_acl:
			sym_get(sym);
			if (sym->code == S_not) {
			    negate = 1;
			    sym_get(sym);
			}
			strset(&acl, sym->buf);
			sym_get(sym);
		    case S_equal:
			parse(sym, S_equal);
			if (su_pton(su, sym->buf))
			    parse_error(sym, "Expected IP address, but got '%s'", sym->buf);
			add_var_acl(sym, &passive_addr, acl, ARG_SU, (char *) su, negate);
			Xfree(&acl);
			sym_get(sym);
		    default:
			parse_error_expect(sym, S_acl, S_equal, S_unknown);
		    }
		    continue;
		}
	    case S_port:
		sym_get(sym);
		switch (sym->code) {
		case S_min:
		    parse_aclconf(sym, ARG_INT, &pasv_ports_first, NULL);
		    continue;
		case S_max:
		    parse_aclconf(sym, ARG_INT, &pasv_ports_last, NULL);
		    continue;
		default:
		    parse_error_expect(sym, S_min, S_max, S_unknown);
		}
	    default:
		parse_error_expect(sym, S_address, S_port, S_unknown);
	    }
	case S_timespec:
	    parse_timespec(timespectable, sym);
	    continue;
	case S_acl:
#if 0
	    acl = <name > {
	    acl_expr +}
	    state =[not] (connect | login | anonymous | real | secure)
		(src | dst) =[not] < cidr >
		arg[regex[ignore - case]] =[not] < string >
		path[regex[ignore - case]] =[not] < string >
		user[regex[ignore - case]] =[not] < string > host[regex[ignore - case]] =[not] < string > time =[not] < timespecname >
#endif
		parse_ftp_acl(sym);
	    continue;
	case S_logformat:
	    sym_get(sym);
	    switch (sym->code) {
	    case S_transfer:
		sym_get(sym);
		parse(sym, S_equal);
		strset(&logformat_transfer, sym->buf);
		sym_get(sym);
		continue;
	    case S_cmd:
	    case S_command:
		sym_get(sym);
		parse(sym, S_equal);
		strset(&logformat_command, sym->buf);
		sym_get(sym);
		continue;
	    case S_event:
		sym_get(sym);
		parse(sym, S_equal);
		strset(&logformat_event, sym->buf);
		sym_get(sym);
		continue;
	    case S_delimiter:
		sym_get(sym);
		parse(sym, S_equal);
		logformat_delimiter = sym->buf[0];
		sym_get(sym);
		continue;
	    case S_substitute:
		sym_get(sym);
		parse(sym, S_equal);
		logformat_substitute = sym->buf[0];
		sym_get(sym);
		continue;
	    default:
		parse_error_expect(sym, S_transfer, S_command, S_delimiter, S_substitute, S_unknown);
	    }
#ifdef WITH_SSL
	case S_ssl:
	case S_tls:
	    sym_get(sym);
	    switch (sym->code) {
	    case S_certfile:
		sym_get(sym);
		parse(sym, S_equal);
		strset(&ssl_cert, sym->buf);
		sym_get(sym);
		continue;
	    case S_keyfile:
		sym_get(sym);
		parse(sym, S_equal);
		strset(&ssl_key, sym->buf);
		sym_get(sym);
		continue;
	    case S_passphrase:
		sym_get(sym);
		parse(sym, S_equal);
		strset(&ssl_pass, sym->buf);
		sym_get(sym);
		continue;
	    case S_auth:
		sym_get(sym);
		parse(sym, S_equal);
		ssl_auth = S_permit == parse_bool(sym);
		continue;
	    case S_cafile:
		sym_get(sym);
		parse(sym, S_equal);
		strset(&ssl_cafile, sym->buf);
		sym_get(sym);
		continue;
	    case S_capath:
		sym_get(sym);
		parse(sym, S_equal);
		strset(&ssl_capath, sym->buf);
		sym_get(sym);
		continue;
	    case S_required:
		sym_get(sym);
		parse(sym, S_equal);
		ssl_auth_req = S_permit == parse_bool(sym);
		continue;
	    case S_depth:
		sym_get(sym);
		parse(sym, S_equal);
		ssl_depth = parse_int(sym);
		continue;
	    case S_ciphers:
		sym_get(sym);
		parse(sym, S_equal);
		strset(&ssl_ciphers, sym->buf);
		sym_get(sym);
		continue;
	    case S_olddraft:
		sym_get(sym);
		parse(sym, S_equal);
		ssl_old_draft = S_permit == parse_bool(sym);
		continue;
	    default:
		parse_error_expect(sym, S_certfile, S_keyfile,
				   S_passphrase, S_auth, S_cafile, S_capath, S_required, S_depth, S_ciphers, S_olddraft, S_unknown);
	    }
#endif

	case S_rewrite:{
#ifdef WITH_PCRE2
		char *a0 = NULL, *a1 = NULL;
		u_int line = sym->line;
		sym->flag_parse_pcre = 1;
		sym_get(sym);
		a0 = alloca(strlen(sym->buf) + 1);
		strcpy(a0, sym->buf);
		sym_get(sym);
		a1 = alloca(strlen(sym->buf) + 1);
		strcpy(a1, sym->buf);
		sym_get(sym);
		sym->flag_parse_pcre = 0;
		if (line == sym->line) {
		    PCRE_add(a0, a1, sym->buf);
		    sym_get(sym);
		} else
		    PCRE_add(a0, a1, NULL);
#else
		parse_error(sym, "%s requires PCRE2 support.", codestring[S_rewrite]);
#endif				/* WITH_PCRE2 */
	    }

	case S_cmd:
	case S_command:{
//  command = site MTDT { (acl [not] AclName = [log] (permit|deny)*  }
		int site_cmd = 0;
		char *co = NULL;

		sym_get(sym);
		parse(sym, S_equal);

		if (sym->code == S_site) {
		    site_cmd = 1;
		    sym_get(sym);
		}
		strset(&co, sym->buf);
		sym_get(sym);
		parse(sym, S_openbra);
		while (sym->code == S_acl) {
		    int log_cmd = 0, negate = 0;
		    struct ftp_acl *acl;
		    sym_get(sym);
		    if (sym->code == S_not) {
			negate = 1;
			sym_get(sym);
		    }
		    acl = lookup_acl(sym, sym->buf);
		    sym_get(sym);
		    parse(sym, S_equal);
		    if (sym->code == S_log) {
			log_cmd = 1;
			sym_get(sym);
		    }
		    acl_add_cmd(co, parse_bool(sym), acl, site_cmd, negate, log_cmd);
		}
		Xfree(&co);
		parse(sym, S_closebra);
		continue;
	    }
	default:
	    parse_error(sym, "'%s' unexpected", sym->buf);
	}
}

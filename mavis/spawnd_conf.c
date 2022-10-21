/*
 * conf.c
 * (C)1998-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include "misc/sysconf.h"
#include "spawnd_headers.h"
#include "misc/ostype.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <netdb.h>
#include "misc/radix.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

struct acl {
    struct acl *next;
    enum token token;
    int negate;
    radixtree_t *addr;
};

static struct acl *acl_start = NULL;
static struct acl *acl_last = NULL;

static void parse_acl(struct sym *sym)
{
    struct acl **acl = &acl_last;
    enum token sc = sym->code;
    int negate = 0;
    struct in6_addr a;
    int cm;

    sym_get(sym);
    if (sym->code == S_not)
	negate = 1;
    if (!acl_last || acl_last->negate != negate || acl_last->token != sc) {
	while (*acl)
	    acl = &(*acl)->next;
	acl = calloc(1, sizeof(struct acl));
	if (!acl_start)
	    acl_start = *acl;
	acl_last = *acl;
    }
    (*acl)->negate = negate;
    (*acl)->token = sc;
    if (!(*acl)->addr)
	(*acl)->addr = radix_new(NULL, NULL);

    if (v6_ptoh(&a, &cm, sym->buf))
	parse_error(sym, "Expected an IP address or network in CIDR " "notation, but got '%s'.", sym->buf);
    radix_add((*acl)->addr, &a, cm, (void *) 1);

    sym_get(sym);
}

static enum token eval_acl(struct in6_addr *addr)
{
    struct acl *acl = acl_start;
    while (acl) {
	int match = radix_lookup(acl->addr, addr, NULL) ? -1 : 0;
	if (acl->negate)
	    match = !match;
	if (match)
	    return acl->token;
	acl = acl->next;
    }
    return acl_start ? S_deny : S_permit;
}

int spawnd_acl_check(sockaddr_union * su)
{
    struct in6_addr a;
    if (su_ptoh(su, &a))
	return -1;
    return S_permit == eval_acl(&a);
}

static void parse_listen(struct sym *sym)
{
    char *address = NULL, *port = NULL;
    struct spawnd_context *ctx = spawnd_new_context(NULL);

    ctx->retry_delay = spawnd_data.retry_delay;
    ctx->listen_backlog = 128;
    ctx->overload_backlog = 128;
    ctx->socktype = SOCK_STREAM;
    ctx->protocol = IPPROTO_TCP;
#ifdef VRF_RTABLE
    ctx->vrf_id = -1;
#endif
    sym_get(sym);

    if (sym->code == S_equal)
	sym_get(sym);

    parse(sym, S_openbra);
    while (sym->code != S_closebra && sym->code != S_eof) {
	switch (sym->code) {
	case S_path:
	case S_address:
	    sym_get(sym);
	    parse(sym, S_equal);
	    strset(&address, sym->buf);
	    sym_get(sym);
	    break;
	case S_port:
	    sym_get(sym);
	    parse(sym, S_equal);
	    strset(&port, sym->buf);
	    sym_get(sym);
	    break;
	case S_realm:
	    sym_get(sym);
	    parse(sym, S_equal);
	    if (strlen(sym->buf) >= SCM_REALM_SIZE)
		parse_error(sym, "Maximum tag length is limited to %d characters.", SCM_REALM_SIZE - 1);
	    strset(&ctx->tag, sym->buf);
	    ctx->tag_len = strlen(ctx->tag);
	    sym_get(sym);
	    break;
	case S_vrf:
	    sym_get(sym);
	    parse(sym, S_equal);
#ifdef VRF_BINDTODEVICE
	    strset(&ctx->vrf, sym->buf);
	    ctx->vrf_len = strlen(ctx->vrf) + 1;
#endif
#ifdef VRF_RTABLE
	    ctx->vrf_id = atoi(sym->buf);
#endif
	    sym_get(sym);
	    break;
	case S_ssl:
	case S_tls:
	    sym_get(sym);
	    parse(sym, S_equal);
	    ctx->use_ssl = parse_bool(sym) ? 1 : 0;
	    break;
	case S_haproxy:
	    sym_get(sym);
	    parse(sym, S_equal);
	    ctx->haproxy = parse_bool(sym) ? 1 : 0;
	    break;
	case S_mode:
	    parse_umask(sym, &ctx->mode);
	    break;
	case S_userid:
	    parse_userid(sym, &ctx->uid, &ctx->gid);
	    break;
	case S_groupid:
	    parse_groupid(sym, &ctx->uid);
	    break;
	case S_backlog:
	    sym_get(sym);
	    parse(sym, S_equal);
	    ctx->listen_backlog = parse_int(sym);
	    break;
	case S_overload:
	    sym_get(sym);
	    parse(sym, S_backlog);
	    parse(sym, S_equal);
	    ctx->overload_backlog = parse_int(sym);
	    break;
	case S_bind:
	    sym_get(sym);
	    parse(sym, S_retry);
	    parse(sym, S_delay);
	    parse(sym, S_equal);
	    ctx->retry_delay = parse_int(sym);
	    break;
	case S_type:
	    sym_get(sym);
	    parse(sym, S_equal);
	    switch (sym->code) {
	    case S_STREAM:
		ctx->socktype = SOCK_STREAM;
		break;
#ifdef SOCK_SEQPACKET
	    case S_SEQPACKET:
		ctx->socktype = SOCK_SEQPACKET;
		break;
#endif
	    default:
		parse_error_expect(sym, S_STREAM,
#ifdef SOCK_SEQPACKET
				   S_SEQPACKET,
#endif
				   S_unknown);
	    }
	    sym_get(sym);
	    break;
	case S_protocol:
	    sym_get(sym);
	    parse(sym, S_equal);
	    switch (sym->code) {
	    case S_TCP:
		ctx->protocol = IPPROTO_TCP;
		break;
#ifdef IPPROTO_SCTP
	    case S_SCTP:
		ctx->protocol = IPPROTO_SCTP;
		break;
#endif
	    default:
		parse_error_expect(sym, S_TCP,
#ifdef IPPROTO_SCTP
				   S_SCTP,
#endif
				   S_unknown);
	    }
	    sym_get(sym);
	    break;
	case S_tcp:
	    sym_get(sym);
	    parse(sym, S_keepalive);
	    switch (sym->code) {
	    case S_count:
		sym_get(sym);
		parse(sym, S_equal);
		ctx->keepcnt = parse_int(sym);
		break;
	    case S_idle:
		sym_get(sym);
		parse(sym, S_equal);
		ctx->keepidle = parse_int(sym);
		break;
	    case S_interval:
		sym_get(sym);
		parse(sym, S_equal);
		ctx->keepintvl = parse_int(sym);
		break;
	    default:
		parse_error_expect(sym, S_count, S_idle, S_interval, S_unknown);
	    }
	    break;
	default:
	    parse_error_expect(sym, S_address, S_path, S_port, S_realm, S_tls, S_userid, S_groupid, S_backlog, S_type, S_protocol, S_retry, S_tcp, S_unknown);
	}
    }
    if (ctx->overload_backlog > ctx->listen_backlog)
	ctx->overload_backlog = ctx->listen_backlog;
    parse(sym, S_closebra);
    if (!common_data.parse_only && su_addrinfo(address ? address : inet_wildcard(), port, SOCK_STREAM, PF_UNSPEC, 0, ctx, spawnd_note_listener))
	logerr("FATAL: \"bind to %s:%s\" failed", address ? address : "(NULL)", port ? port : "(NULL)");
    Xfree(&address);
    Xfree(&port);
}

void spawnd_parse_decls(struct sym *sym)
{
    /* Top level of parser */
    while (1)
	switch (sym->code) {
	    case_CC_Tokens;
	case S_closebra:
	case S_eof:
	    fflush(stderr);
	    return;
	case S_permit:
	case S_deny:
	    parse_acl(sym);
	    continue;
	case S_listen:
	    parse_listen(sym);
	    continue;
	case S_background:
	    sym_get(sym);
	    parse(sym, S_equal);
	    if (spawnd_data.background_lock)
		parse_bool(sym);
	    else
		spawnd_data.background = parse_bool(sym);
	    continue;
	case S_bind:
	    sym_get(sym);
	    parse(sym, S_retry);
	    parse(sym, S_delay);
	    parse(sym, S_equal);
	    spawnd_data.retry_delay = parse_int(sym);
	    continue;
	case S_tcp:
	    sym_get(sym);
	    switch (sym->code) {
	    case S_keepalive:
		sym_get(sym);
		switch (sym->code) {
		case S_count:
		    sym_get(sym);
		    parse(sym, S_equal);
		    spawnd_data.keepcnt = parse_int(sym);
		    break;
		case S_idle:
		    sym_get(sym);
		    parse(sym, S_equal);
		    spawnd_data.keepidle = parse_int(sym);
		    break;
		case S_interval:
		    sym_get(sym);
		    parse(sym, S_equal);
		    spawnd_data.keepintvl = parse_int(sym);
		    break;
		default:
		    parse_error_expect(sym, S_count, S_idle, S_interval, S_unknown);
		}
		continue;
	    case S_bufsize:
		sym_get(sym);
		parse(sym, S_equal);
		spawnd_data.scm_bufsize = parse_int(sym);
		break;
	    default:
		parse_error_expect(sym, S_bufsize, S_keepalive, S_unknown);
	    }
	    continue;
	case S_pidfile:
	case S_pid_file:
	    sym_get(sym);
	    parse(sym, S_equal);
	    if (!spawnd_data.pidfile_lock)
		strset(&spawnd_data.pidfile, sym->buf);
	    sym_get(sym);
	    continue;
	case S_overload:
	    sym_get(sym);
	    parse(sym, S_equal);
	    switch (sym->code) {
	    case S_reset:
	    case S_queue:
	    case S_close:
		spawnd_data.overload = sym->code;
		break;
	    default:
		parse_error_expect(sym, S_close, S_queue, S_reset, S_unknown);
	    }
	    sym_get(sym);
	    continue;
	case S_single:
	    sym_get(sym);
	    parse(sym, S_process);
	    parse(sym, S_equal);
	    common_data.singleprocess = parse_bool(sym);
	    continue;
	case S_spawn:
	    sym_get(sym);
	    if (sym->code == S_equal)
		sym_get(sym);
	    parse(sym, S_openbra);
	    while (sym->code != S_closebra && sym->code != S_eof) {
		switch (sym->code) {
		case S_exec:{
			char tmp[1024];
			sym_get(sym);
			parse(sym, S_equal);
			ostypef(sym->buf, tmp, sizeof(tmp));
			if (access(tmp, X_OK))
			    parse_error(sym, "File %s doesn't appear to be executable", tmp);
			strset(&spawnd_data.child_path, tmp);
			sym_get(sym);
			break;
		    }
		case S_id:
		    sym_get(sym);
		    parse(sym, S_equal);
		    strset(&spawnd_data.child_id, sym->buf);
		    sym_get(sym);
		    break;
		case S_config:
		    sym_get(sym);
		    parse(sym, S_equal);
		    strset(&spawnd_data.child_config, sym->buf);
		    sym_get(sym);
		    break;
		case S_instances:
		    sym_get(sym);
		    switch (sym->code) {
		    case S_min:
			sym_get(sym);
			parse(sym, S_equal);
			common_data.servers_min = parse_int(sym);
			break;
		    case S_max:
			sym_get(sym);
			parse(sym, S_equal);
			common_data.servers_max = parse_int(sym);
			break;
		    default:
			parse_error_expect(sym, S_min, S_max, S_unknown);
		    }
		    break;
#ifdef WITH_IPC
		case S_ipc:
		    sym_get(sym);
		    parse(sym, S_key);
		    parse(sym, S_equal);
		    common_data.ipc_key = parse_int(sym);
		    break;
#endif
		case S_users:
		    sym_get(sym);
		    switch (sym->code) {
		    case S_min:
			sym_get(sym);
			parse(sym, S_equal);
			common_data.users_min = parse_int(sym);
			break;
		    case S_max:
			sym_get(sym);
			parse(sym, S_equal);
			common_data.users_max = parse_int(sym);
			break;
		    default:
			parse_error_expect(sym, S_min, S_max, S_unknown);
		    }
		    break;
		case S_userid:
		    parse_userid(sym, &spawnd_data.uid, &spawnd_data.gid);
		    break;
		case S_groupid:
		    parse_groupid(sym, &spawnd_data.gid);
		    break;
		case S_working:
		    sym_get(sym);
		    parse(sym, S_directory);
		    sym_get(sym);
		    parse(sym, S_equal);
		    strset(&spawnd_data.cwd, sym->buf);
		    sym_get(sym);
		    break;
		case S_sticky:
		    sym_get(sym);
		    parse(sym, S_cache);
		    switch (sym->code) {
		    case S_period:
			sym_get(sym);
			parse(sym, S_equal);
			spawnd_data.tracking_period = parse_int(sym);
			break;
		    case S_size:
			sym_get(sym);
			parse(sym, S_equal);
			spawnd_data.tracking_size = parse_int(sym);
			break;
		    default:
			parse_error_expect(sym, S_period, S_size, S_unknown);
		    }
		    break;
		default:
		    parse_error_expect(sym, S_exec, S_id, S_config, S_instances, S_users, S_userid, S_groupid, S_ipc, S_unknown);
		}
	    }
	    parse(sym, S_closebra);
#ifdef WITH_IPC
	    if (!common_data.parse_only && common_data.ipc_key) {
		if (spawnd_data.gid)
		    setegid(spawnd_data.gid);
		if (spawnd_data.uid)
		    seteuid(spawnd_data.uid);
		if (strcmp(spawnd_data.conffile, spawnd_data.child_config)) {
		    char *buf;
		    int buflen;
		    if (!cfg_open_and_read(spawnd_data.conffile, &buf, &buflen)) {
			if (!ipc_create(buf, buflen))
			    strset(&spawnd_data.child_config, common_data.ipc_url);
			cfg_close(spawnd_data.conffile, buf, buflen);
		    }
		} else {
		    if (!ipc_create(sym->in, sym->len))
			strset(&spawnd_data.child_config, common_data.ipc_url);
		}
		if (spawnd_data.gid)
		    setegid(getgid());
		if (spawnd_data.uid)
		    seteuid(getuid());
	    }
#endif
	    continue;
	default:
	    parse_error(sym, "'%s' unexpected", sym->buf);
	}
}

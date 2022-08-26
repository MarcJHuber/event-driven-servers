/*
 * conf.c (C)1998-2011 by Marc Huber <Marc.Huber@web.de>
 *
 * $Id$
 *
 */

#include "misc/net.h"
#include "mavisd/headers.h"
#include "misc/memops.h"
#include "misc/radix.h"
#include "misc/sysconf.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

struct socket_info {
    struct blowfish_ctx *blowfish;
    uid_t uid;
    gid_t gid;
    int sock;
    mode_t mode;
};

static int init_rcvr(sockaddr_union * su, void *data)
{
    int recvbufsize_initial = 262144, recvbufsize_min = 65536, recvbufsize;
    socklen_t recvbufsizelen = (socklen_t) sizeof(recvbufsize);
    struct context *c = Xcalloc(1, sizeof(struct context));
    c->io = io;
    c->sock = -1;
    c->sock = ((struct socket_info *) data)->sock;
    c->blowfish = ((struct socket_info *) data)->blowfish;
    c->uid = ((struct socket_info *) data)->uid;
    c->gid = ((struct socket_info *) data)->gid;
    c->mode = ((struct socket_info *) data)->mode;
    c->sa = *su;

    if ((c->sock = su_socket(c->sa.sa.sa_family, SOCK_DGRAM, 0)) < 0) {
	logerr("socket");
	return (-1);
    }
#ifdef AF_UNIX
    if (c->sa.sa.sa_family == AF_UNIX)
	unlink(c->sa.sun.sun_path);
#endif				/* AF_UNIX */

    setproctitle("%s: binding to socket", common_data.progname);

    if (c->sock && (su_bind(c->sock, &c->sa) < 0)) {
	logerr("bind");
	return -1;
    }
#ifdef AF_UNIX
    if (c->sa.sa.sa_family == AF_UNIX) {
	if (chown(c->sa.sun.sun_path, c->uid, c->gid) || chmod(c->sa.sun.sun_path, c->mode)) {
	    //FIXME
	}
    }
#endif				/* AF_UNIX */

    for (recvbufsize = recvbufsize_initial;
	 recvbufsize > 0 && setsockopt(c->sock, SOL_SOCKET, SO_RCVBUF,
				       (char *) &recvbufsize, (socklen_t) sizeof(recvbufsize)) < 0; recvbufsize -= recvbufsize_min);

    if (!getsockopt(c->sock, SOL_SOCKET, SO_RCVBUF, (char *) &recvbufsize, &recvbufsizelen))
	logmsg("receive buffer size set to %d bytes", recvbufsize);

    Debug((DEBUG_PROC, "sock is %d\n", c->sock));
    io_register(io, c->sock, c);
    io_set_cb_i(io, c->sock, (void *) client_io);
    io_set_cb_e(io, c->sock, (void *) udp_error);
    io_set_cb_h(io, c->sock, (void *) udp_error);
    io_set_i(io, c->sock);

    return 0;
}


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
	*acl = calloc(1, sizeof(struct acl));
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

int acl_check(sockaddr_union * su)
{
    struct in6_addr a;
    if (su_ptoh(su, &a))
	return -1;
    return S_permit == eval_acl(&a);
}

static void parse_listen(struct sym *sym)
{
    struct socket_info si;
    char blowfish_key[73];
    ssize_t blowfish_key_len = 0;
    char *address = NULL, *port = NULL;
    int fn;

    memset(&si, 0, sizeof(si));
    si.sock = -1;

    sym_get(sym);
    parse(sym, S_equal);
    parse(sym, S_openbra);
    while (sym->code != S_closebra && sym->code != S_eof) {
	switch (sym->code) {
	case S_path:
	case S_address:
	    sym_get(sym);
	    parse(sym, S_equal);
	    address = alloca(strlen(sym->buf) + 1);
	    strcpy(address, sym->buf);
	    sym_get(sym);
	    continue;
	case S_port:
	    sym_get(sym);
	    parse(sym, S_equal);
	    port = alloca(strlen(sym->buf) + 1);
	    strcpy(port, sym->buf);
	    sym_get(sym);
	    continue;
	case S_mode:
	    parse_umask(sym, &si.mode);
	    continue;
	case S_userid:
	    parse_userid(sym, &si.uid, &si.gid);
	    continue;
	case S_groupid:
	    parse_groupid(sym, &si.uid);
	    continue;
	case S_blowfish:
	    sym_get(sym);
	    switch (sym->code) {
	    case S_key:
		sym_get(sym);
		parse(sym, S_equal);
		strncpy(blowfish_key, sym->buf, 72);
		blowfish_key[72] = 0;
		blowfish_key_len = strlen(blowfish_key);
		sym_get(sym);
		break;
	    case S_keyfile:
		sym_get(sym);
		parse(sym, S_equal);
		fn = open(sym->buf, O_RDONLY);
		if (fn > -1) {
		    blowfish_key_len = read(fn, blowfish_key, 72);
		    close(fn);
		    if (blowfish_key_len < 0)
			blowfish_key_len = 0;
		} else
		    logerr("FATAL: open %s", sym->buf);
		sym_get(sym);
		break;
	    default:
		parse_error_expect(sym, S_key, S_keyfile, S_unknown);
	    }

	    if (blowfish_key_len > 0)
		si.blowfish = blowfish_init(blowfish_key, blowfish_key_len);
	    else
		si.blowfish = NULL;
	    continue;
	default:
	    parse_error_expect(sym, S_address, S_path, S_port, S_tls, S_userid, S_groupid, S_unknown);
	}
    }
    parse(sym, S_closebra);
    if (su_addrinfo(address ? address : "0.0.0.0", port, SOCK_STREAM, PF_UNSPEC, 0, &si, init_rcvr))
	logerr("FATAL: \"bind to %s:%s\" failed", address ? address : "(NULL)", port ? port : "(NULL)");
}


void parse_decls(struct sym *sym)
{
    /* Top level of parser */
    while (1)
	switch (sym->code) {
	case S_closebra:
	case S_eof:
	    return;
	case S_permit:
	case S_deny:
	    parse_acl(sym);
	    continue;
	    case_CC_Tokens;
	case S_background:
	    sym_get(sym);
	    parse(sym, S_equal);
	    background = parse_bool(sym);
	    break;
	case S_pidfile:
	case S_pid_file:
	    sym_get(sym);
	    parse(sym, S_equal);
	    strset(&pidfile, sym->buf);
	    sym_get(sym);
	    break;
	case S_stat:
	    sym_get(sym);
	    parse(sym, S_period);
	    parse(sym, S_equal);
	    stat_period = (u_long) parse_int(sym);
	    break;
	case S_transmit:
	    sym_get(sym);
	    parse(sym, S_password);
	    parse(sym, S_equal);
	    transmit_password = parse_bool(sym);
	    break;
	case S_listen:
	    parse_listen(sym);
	    break;
	case S_mavis:
	    sym_get(sym);
	    switch (sym->code) {
	    case S_module:
		if (parse_mavismodule(&mcx, NULL, sym))
		    scm_fatal();
		continue;
	    case S_path:
		parse_mavispath(sym);
		continue;
		case_CC_Tokens;
	    default:
		parse_error_expect(sym, S_module, S_path, S_unknown);
	    }
	default:
	    parse_error(sym, "'%s' unexpected", sym->buf);
	}
}

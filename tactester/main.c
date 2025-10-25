/*
 * main.c
 *
 * AAA test client for TACACS+ and RADIUS
 *
 * (C)2025 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include "aaa.h"
#include "misc/memops.h"
#include "mavis/mavis.h"
#include "misc/version.h"
#include "tac_plus-ng/protocol_tacacs.h"
#include "tac_plus-ng/config_radius.h"

static const char rcsid[] __attribute__((used)) = "$Id$";
extern int optind, opterr;
extern char *optarg;

static struct conn *conn = NULL;

static void parse_server(struct sym *sym, int skip)
{
    sym_get(sym);
    parse(sym, S_openbra);
    char *d_port = NULL;
    char *d_addr = NULL;
    while (1) {
	switch (sym->code) {
	case S_eof:
	    parse_error(sym, "EOF unexpected");
	case S_closebra:
	    sym_get(sym);
	    if (skip)
		return;
	    if (!d_port)
		parse_error(sym, "Destination port not set\n");
	    if (!d_addr)
		parse_error(sym, "Destination address not set\n");
	    strcat(d_addr, ":");
	    strcat(d_addr, d_port);
	    if (conn_set_peer(conn, d_addr))
		parse_error(sym, "Destination %s not parsable\n", d_addr);
	    return;
	case S_protocol:
	    sym_get(sym);
	    parse(sym, S_equal);
	    switch (sym->code) {
	    case S_tacacs_tcp:
	    case S_tacacs_tls:
	    case S_radius_udp:
	    case S_radius_tcp:
	    case S_radius_tls:
	    case S_radius_dtls:
		if (!skip)
		    conn_set_transport(conn, sym->code);
		break;
	    default:
		parse_error_expect(sym, S_tacacs_tcp, S_tacacs_tls, S_radius_udp, S_radius_tcp, S_radius_tls, S_radius_dtls, S_unknown);
	    }
	    sym_get(sym);
	    continue;
	case S_destination:
	    sym_get(sym);
	    switch (sym->code) {
	    case S_address:{
		    sym_get(sym);
		    parse(sym, S_equal);
		    if (!skip) {
			size_t len = strlen(sym->buf);
			d_addr = alloca(len + 10);
			memcpy(d_addr, sym->buf, len + 1);
		    }
		    sym_get(sym);
		    continue;
		}
	    case S_port:{
		    sym_get(sym);
		    parse(sym, S_equal);
		    if (!skip) {
			size_t len = strlen(sym->buf);
			d_port = alloca(len + 1);
			memcpy(d_port, sym->buf, len + 1);
		    }
		    sym_get(sym);
		    continue;
		}
	    default:
		parse_error_expect(sym, S_address, S_port, S_unknown);
	    }
	    continue;
	case S_source:
	    sym_get(sym);
	    parse(sym, S_address);
	    parse(sym, S_equal);
	    if (!skip && conn_set_local(conn, sym->buf))
		parse_error(sym, "Source address %s not parseable\n", sym->buf);
	    sym_get(sym);
	    continue;
	case S_tls:
	    sym_get(sym);
	    switch (sym->code) {
	    case S_cert_file:
		sym_get(sym);
		parse(sym, S_equal);
		if (!skip)
		    conn_set_tls_cert(conn, sym->buf);
		sym_get(sym);
		continue;
	    case S_key_file:
		sym_get(sym);
		parse(sym, S_equal);
		if (!skip)
		    conn_set_tls_key(conn, sym->buf);
		sym_get(sym);
		continue;
	    case S_cafile:
		sym_get(sym);
		parse(sym, S_equal);
		if (!skip)
		    conn_set_tls_peer_ca(conn, sym->buf);
		sym_get(sym);
		continue;
	    case S_sni:
		sym_get(sym);
		parse(sym, S_equal);
		if (!skip)
		    conn_set_tls_peer_sni(conn, sym->buf);
		sym_get(sym);
		continue;
	    case S_alpn:
		sym_get(sym);
		parse(sym, S_equal);
		if (!skip)
		    conn_set_tls_alpn(conn, sym->buf);
		sym_get(sym);
		continue;
	    case S_psk:
		sym_get(sym);
		switch (sym->code) {
		case S_hint:
		    sym_get(sym);
		    parse(sym, S_equal);
		    if (!skip)
			conn_set_tls_psk_hint(conn, sym->buf, strlen(sym->buf));
		    sym_get(sym);
		    continue;
		case S_id:
		    sym_get(sym);
		    parse(sym, S_equal);
		    if (!skip)
			conn_set_tls_psk_id(conn, sym->buf, strlen(sym->buf));
		    sym_get(sym);
		    continue;
		case S_key:
		    sym_get(sym);
		    parse(sym, S_equal);
		    if (!skip)
			conn_set_tls_psk(conn, sym->buf, strlen(sym->buf));
		    sym_get(sym);
		    continue;
		default:
		    parse_error_expect(sym, S_key, S_hint, S_id, S_unknown);
		}
	    default:
		parse_error_expect(sym, S_cert_file, S_key_file, S_cafile, S_sni, S_alpn, S_psk, S_unknown);
	    }
	    continue;
	case S_timeout:
	    sym_get(sym);
	    parse(sym, S_equal);
	    if (skip)
		parse_int(sym);
	    else
		conn_set_timeout(conn, parse_int(sym), 0);
	    continue;
	case S_retry:
	    sym_get(sym);
	    parse(sym, S_equal);
	    if (skip)
		parse_int(sym);
	    else
		conn->retries = parse_int(sym);
	    continue;
	case S_key:
	    sym_get(sym);
	    parse(sym, S_equal);
	    if (!skip)
		conn_set_key(conn, sym->buf);
	    sym_get(sym);
	    continue;
	default:
	    parse_error_expect(sym, S_key, S_retry, S_timeout, S_tls, S_source, S_destination, S_protocol, S_closebra, S_unknown);
	}
    }
}

static char *arg_server = NULL;

static void myparse(struct sym *sym)
{
    while (1) {
	switch (sym->code) {
	case S_radius_dictionary:
	    parse_radius_dictionary(sym);
	    continue;
	case S_server:
	    sym_get(sym);
	    if (!arg_server || !strcmp(arg_server, sym->buf)) {
		arg_server = strdup(sym->buf);
		parse_server(sym, 0);
	    } else
		parse_server(sym, 1);
	    continue;
	case S_closebra:
	    return;
	case S_eof:
	    parse_error(sym, "EOF unexpected");

	default:
	    parse_error_expect(sym, S_server, S_radius_dictionary, S_closebra, S_unknown);
	}
    }
}

static char *arg_user = "demo";
static char *arg_pass = "demo";
static char *arg_tty = "0";
static char *arg_remoteip = "127.0.0.1";
static char *arg_config = "/usr/local/etc/tactester.cfg";
static char *arg_config_id = "tactester";

static void usage()
{
    fprintf(stderr, "\n");
    fprintf(stderr, "Usage: tactester [options] [attributes ...]\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -P                  parse only\n");
    fprintf(stderr, "  -d <debuglevel>     (set debug level)\n");
    fprintf(stderr, "  -A <attribute>      attributes for acct/authz\n");
    fprintf(stderr, "  -u <user>           user name [%s]\n", arg_user);
    fprintf(stderr, "  -p <password>       user password [%s]\n", arg_pass);
    fprintf(stderr, "  -m <mode>           (authc, authz, acct) [authz]\n");
    fprintf(stderr, "  -R <client_ip>      remote client ip [127.0.0.1]\n");
    fprintf(stderr, "  -T <tty_port>       tty name [%s]\n", arg_tty);
    fprintf(stderr, "  -A <authen_type>    TACACS+ authen_type (ascii, pap) [ascii]\n");
    fprintf(stderr, "  -M <authen_method>  [tacacsplus]\n");
    fprintf(stderr, "  -S <authen_service> TACACS+ authen_service (login, enable) [login]\n");
    fprintf(stderr, "  -C <config_file>    [%s]\n", arg_config);
    fprintf(stderr, "  -I <config_id>      [%s]\n", arg_config_id);
    fprintf(stderr, "  -s <server>         [first found]\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Author:  Marc.Huber@web.de\n");
    fprintf(stderr, "GIT:     https://github.com/MarcJHuber/event-driven-servers/\n");
    fprintf(stderr, "Version: " VERSION "\n");
    fprintf(stderr, "\n");
    exit(-1);
}

int main(int argc, char *argv[])
{
    char opt, *optstring = "d:PA:u:p:m:R:T:A:M:S:C:I:s:";

#define AAA_AUTHC 0
#define AAA_AUTHZ 1
#define AAA_ACCT 2

    int mode = AAA_AUTHZ;
    int tac_authen_pap = 0;
    int tac_authen_svc = TAC_PLUS_AUTHEN_SVC_LOGIN;
    int tac_authen_meth = TAC_PLUS_AUTHEN_METH_TACACSPLUS;

    init_common_data();

    while ((opt = getopt(argc, argv, optstring)) != CHAREOF)
	switch (opt) {
	case 'P':
	    common_data.parse_only = 1;
	    break;
	case 'd':
	    common_data.debug = atoi(optarg);
	    break;
	case 'u':
	    arg_user = optarg;
	    break;
	case 'p':
	    arg_pass = optarg;
	    mode = AAA_AUTHC;
	    break;
	case 'R':
	    arg_remoteip = optarg;
	    break;
	case 'T':
	    arg_tty = optarg;
	    break;
	case 'C':
	    arg_config = optarg;
	    break;
	case 'I':
	    arg_config_id = optarg;
	    break;
	case 's':
	    arg_server = optarg;
	    break;
	case 'm':
	    if (!strcmp(optarg, "authc"))
		mode = AAA_AUTHC;
	    else if (!strcmp(optarg, "authz"))
		mode = AAA_AUTHZ;
	    else if (!strcmp(optarg, "acct"))
		mode = AAA_ACCT;
	    else {
		fprintf(stderr, "Unknown mode \"%s\"s, recognized modes are: authc authz acct\n", optarg);
		exit(-1);
	    }
	    break;
	case 'A':
	    if (!strcmp(optarg, "pap"))
		tac_authen_pap = 1;
	    else if (!strcmp(optarg, "ascii"))
		tac_authen_pap = 0;
	    else {
		fprintf(stderr, "Unknown TACACS+ authentication mode \"%s\"s, recognized modes are: ascii pap\n", optarg);
		exit(-1);
	    }
	    break;
	    if (!strcmp(optarg, "none"))
		tac_authen_meth = 1;
	    else if (!strcmp(optarg, "line"))
		tac_authen_meth = TAC_PLUS_AUTHEN_METH_LINE;
	    else if (!strcmp(optarg, "enable"))
		tac_authen_meth = TAC_PLUS_AUTHEN_METH_ENABLE;
	    else if (!strcmp(optarg, "local"))
		tac_authen_meth = TAC_PLUS_AUTHEN_METH_LOCAL;
	    else if (!strcmp(optarg, "tacplus"))
		tac_authen_meth = TAC_PLUS_AUTHEN_METH_TACACSPLUS;
	    else if (!strcmp(optarg, "radius"))
		tac_authen_meth = TAC_PLUS_AUTHEN_METH_RADIUS;
	    else {
		fprintf(stderr, "Unknown TACACS+ authentication mode \"%s\"s, recognized modes are: ascii pap\n", optarg);
		exit(-1);
	    }
	    break;
	case 'S':
	    if (!strcmp(optarg, "login"))
		tac_authen_svc = TAC_PLUS_AUTHEN_SVC_LOGIN;
	    else if (!strcmp(optarg, "enable"))
		tac_authen_svc = TAC_PLUS_AUTHEN_SVC_ENABLE;
	    else {
		fprintf(stderr, "Unknown TACACS+ authentication service \"%s\", recognized modes are: login enable\n", optarg);
		exit(-1);
	    }
	    break;
	default:
	    usage();
	}

    conn = conn_new();

    cfg_read_config(arg_config, myparse, arg_config_id);
    if (common_data.parse_only)
	exit(0);

    conn_connect(conn);
    struct aaa *aaa = aaa_new(conn);
    aaa_set_tac_authen_pap(aaa, tac_authen_pap);
    aaa_set_tac_authen_svc(aaa, tac_authen_svc);
    aaa_set_tac_authen_meth(aaa, tac_authen_meth);


    argv = &argv[optind];
    argc -= optind;

    while (*argv) {
	aaa_set(aaa, (u_char *) * argv, strlen(*argv));
	argv++;
    }

    if (mode == AAA_AUTHC) {
	if (aaa_authc(aaa, arg_user, arg_remoteip, arg_tty, arg_pass))
	    printf("authc nak\n");
	else
	    printf("authc ack\n");
    } else if (mode == AAA_AUTHZ) {
	if (aaa_authz(aaa, arg_user, arg_remoteip, arg_tty))
	    printf("authz nak\n");
	else
	    printf("authz ack\n");
    } else if (mode == AAA_ACCT) {
	if (aaa_acct(aaa, arg_user, arg_remoteip, arg_tty))
	    printf("acct nak\n");
	else
	    printf("acct ack\n");
    }

    for (int i = 0; i < aaa->ic; i++) {
	printf("%.*s\n", (int) aaa->iv[i].iov_len, (char *) aaa->iv[i].iov_base);
    }

    aaa_free(aaa);

    conn_close(conn);
    exit(EX_OK);
}

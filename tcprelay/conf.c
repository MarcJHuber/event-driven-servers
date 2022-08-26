/*
 * conf.c
 * (C)1998-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include "headers.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

void parse_decls(struct sym *sym)
{
    /* Top level of parser */
    while (1)
	switch (sym->code) {
	case S_closebra:
	case S_eof:
	    return;
	    case_CC_Tokens;
#ifdef WITH_SSL
	case S_ssl:
	case S_tls:
	    sym_get(sym);
	    switch (sym->code) {
	    case S_certfile:
	    case S_cert_file:
		sym_get(sym);
		parse(sym, S_equal);
		strset(&ssl_cert, sym->buf);
		sym_get(sym);
		continue;
	    case S_keyfile:
	    case S_key_file:
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
	    default:
		parse_error_expect(sym, S_cert_file, S_key_file, S_passphrase, S_unknown);
	    }
#endif
	case S_rebalance:
	    sym_get(sym);
	    parse(sym, S_equal);
	    rebalance = parse_int(sym);
	    continue;
	case S_idle:
	    sym_get(sym);
	    parse(sym, S_timeout);
	    parse(sym, S_equal);
	    conntimeout = (u_long) parse_int(sym);
	    continue;
	case S_retire:
	    sym_get(sym);
	    parse(sym, S_limit);
	    parse(sym, S_equal);
	    id_max = (u_long) parse_int(sym);
	    continue;
	case S_remote:
	    {
		char *ad = NULL, *po = NULL;
		int protocol = 0;
		int weight = 1;
		uint16_t p;

		sym_get(sym);
		parse(sym, S_equal);
		parse(sym, S_openbra);
		while (sym->code != S_closebra && sym->code != S_eof) {
		    switch (sym->code) {
		    case S_address:
			sym_get(sym);
			parse(sym, S_equal);
			strset(&ad, sym->buf);
			sym_get(sym);
			continue;
		    case S_port:
			sym_get(sym);
			parse(sym, S_equal);
			strset(&po, sym->buf);
			sym_get(sym);
			continue;
		    case S_protocol:
			sym_get(sym);
			parse(sym, S_equal);
			switch (sym->code) {
			case S_TCP:
			    protocol = IPPROTO_TCP;
			    break;
#ifdef IPPROTO_SCTP
			case S_SCTP:
			    protocol = IPPROTO_SCTP;
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

		    case S_weight:
			sym_get(sym);
			parse(sym, S_equal);
			weight = parse_int(sym);
			continue;
		    default:
			parse_error_expect(sym, S_address, S_port, S_protocol, S_weight, S_unknown);
		    }
		}
		parse(sym, S_closebra);

		con_arr = Xrealloc(con_arr, (con_arr_len + 1) * sizeof(struct connect_address_s));

		memset(&con_arr[con_arr_len], 0, sizeof(struct connect_address_s));

		if (service_to_port(&p, po, SOCK_STREAM))
		    parse_error(sym, "Expected an service or port, but got '%s'", sym->buf);

		if (su_pton_p(&con_arr[con_arr_len].sa, ad, p))
		    parse_error(sym, "Expected an IP address, but got '%s'", sym->buf);

		con_arr[con_arr_len].protocol = protocol;
		con_arr[con_arr_len].weight = weight;
		if (con_arr[con_arr_len].weight < 1)
		    con_arr[con_arr_len].weight = 1;
		con_arr_len++;
		Xfree(&ad);
		Xfree(&po);
		continue;
	    }
	case S_local:
	    sym_get(sym);
	    parse(sym, S_address);
	    parse(sym, S_equal);
	    if (!lcladdr)
		lcladdr = Xcalloc(1, sizeof(sockaddr_union));
	    if (su_pton(lcladdr, sym->buf))
		parse_error(sym, "Expected an IP address, but got '%s'", sym->buf);

	    sym_get(sym);
	    continue;

	default:
	    parse_error(sym, "'%s' unexpected", sym->buf);
	}
}

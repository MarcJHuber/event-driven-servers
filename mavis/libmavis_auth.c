/*
 * libmavis_auth.c
 *
 * (C) 2000-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#define MAVIS_name "auth"

#include "misc/memops.h"
#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include "debug.h"
#include "misc/tohex.h"
#include "misc/base64.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

#define CERTAUTH_NOCERT		0
#define CERTAUTH_CERT		1
#define CERTAUTH_REQUIRED	2
#define CERTAUTH_SUFFICIENT	4

#define MAVIS_CTX_PRIVATE	\
	int authmode;

#include "mavis.h"

#define HAVE_mavis_recv_out
static int mavis_recv_out(mavis_ctx * mcx, av_ctx ** ac)
{
    char *in_result = av_get(*ac, AV_A_RESULT);
    char *in_dbpass = av_get(*ac, AV_A_DBPASSWORD);
    char *in_certsubj = av_get(*ac, AV_A_CERTSUBJ);
    char *in_dbcertsubj = av_get(*ac, AV_A_DBCERTSUBJ);
    char *in_password = av_get(*ac, AV_A_PASSWORD);

    DebugIn(DEBUG_AV);

    if (in_result || (!in_dbpass && !in_dbcertsubj)) {
	av_set(*ac, AV_A_RESULT, AV_V_RESULT_NOTFOUND);
	DebugOut(DEBUG_AV);
	return MAVIS_FINAL;
    }

    if (mcx->authmode & CERTAUTH_CERT) {
	if (in_certsubj && in_dbcertsubj) {
	    char *t, *a = alloca(strlen(in_dbcertsubj) + 1);
	    int found = 0;

	    strcpy(a, in_dbcertsubj);

	    for (t = strtok(a, "\r"); t && !found; t = strtok(NULL, "\r"))
		if (!strcasecmp(in_certsubj, t))
		    found = 1;

	    if (!found) {
		av_set(*ac, AV_A_COMMENT, "certificate mismatch");
		if (mcx->authmode & CERTAUTH_REQUIRED) {
		    av_set(*ac, AV_A_RESULT, AV_V_RESULT_FAIL);
		    DebugOut(DEBUG_AV);
		    return MAVIS_FINAL;
		}
	    } else if (mcx->authmode & CERTAUTH_SUFFICIENT) {
		av_set(*ac, AV_A_RESULT, AV_V_RESULT_OK);
		av_set(*ac, AV_A_COMMENT, "certificate");
		DebugOut(DEBUG_AV);
		return MAVIS_FINAL;
	    }
	} else {
	    av_set(*ac, AV_A_COMMENT, "certificate missing");
	    if (mcx->authmode & CERTAUTH_REQUIRED) {
		av_set(*ac, AV_A_RESULT, AV_V_RESULT_FAIL);
		DebugOut(DEBUG_AV);
		return MAVIS_FINAL;
	    }
	}
    }

    if (!in_dbpass) {
	av_set(*ac, AV_A_RESULT, AV_V_RESULT_NOTFOUND);
	DebugOut(DEBUG_AV);
	return MAVIS_FINAL;
    }

    if (in_password) {
	if (!strcmp(in_dbpass, in_password))
	    av_set(*ac, AV_A_RESULT, AV_V_RESULT_OK);
	else {
	    av_set(*ac, AV_A_COMMENT, "password mismatch");
	    av_set(*ac, AV_A_RESULT, AV_V_RESULT_FAIL);
	}
	DebugOut(DEBUG_AV);
	return MAVIS_FINAL;
    } else
	av_set(*ac, AV_A_COMMENT, "password not set");

    av_set(*ac, AV_A_RESULT, AV_V_RESULT_FAIL);

    Debug((DEBUG_AV, "- %s (failure)\n", __func__));
    return MAVIS_FINAL;
}

/*
authmode = cert(required | sufficient)
*/
#define HAVE_mavis_parse_in
static int mavis_parse_in(mavis_ctx * mcx, struct sym *sym)
{
    while (1) {
	switch (sym->code) {
	case S_script:
	    mavis_script_parse(mcx, NULL, sym);
	    continue;
	case S_authmode:
	    sym_get(sym);
	    parse(sym, S_equal);
	    parse(sym, S_cert);
	    mcx->authmode |= CERTAUTH_CERT;

	    switch (sym->code) {
	    case S_required:
		mcx->authmode |= CERTAUTH_REQUIRED;
		sym_get(sym);
		break;
	    case S_sufficient:
		mcx->authmode |= CERTAUTH_SUFFICIENT;
		sym_get(sym);
		break;
	    default:;
	    }
	    continue;
	case S_eof:
	case S_closebra:
	    return MAVIS_CONF_OK;
	case S_action:
	    mavis_module_parse_action(mcx, sym);
	    continue;
	default:
	    parse_error_expect(sym, S_script, S_authmode, S_action, S_closebra, S_unknown);
	}
    }
}

#define HAVE_mavis_new
static void mavis_new(mavis_ctx * mcx)
{
    mcx->authmode = CERTAUTH_NOCERT;
}

#include "mavis_glue.c"

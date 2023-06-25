/*
 * libmavis_log.c
 *
 * (C)1998-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#define MAVIS_name "log"

#include "misc/memops.h"
#include "mavis.h"
#include "debug.h"
#include "log.h"
#include <string.h>
#include <dlfcn.h>

static const char rcsid[] __attribute__((used)) = "$Id$";

#define HAVE_mavis_parse_in
static int mavis_parse_in(mavis_ctx * mcx, struct sym *sym)
{
    while (1) {
	switch (sym->code) {
	case S_script:
	    mavis_script_parse(mcx, sym);
	    continue;
	case S_eof:
	case S_closebra:
	    return MAVIS_CONF_OK;
	case S_action:
	    mavis_module_parse_action(mcx, sym);
	    continue;
	default:
	    parse_error_expect(sym, S_script, S_action, S_unknown);
	}
    }
}

#define HAVE_mavis_recv_out
static int mavis_recv_out(void *pcx __attribute__((unused)), av_ctx ** ac)
{
    char *avresult = av_get(*ac, AV_A_RESULT);
    char *avcomment = av_get(*ac, AV_A_COMMENT);
    char *avtype = av_get(*ac, AV_A_TYPE);
    char *avuser = av_get(*ac, AV_A_USER);
    char *avipaddr = av_get(*ac, AV_A_IPADDR);

    if (!avresult)
	avresult = AV_V_RESULT_NOTFOUND;

    if (avtype) {
	if (avuser && avipaddr && (!strcmp(avtype, AV_V_TYPE_FTP)
				   || !strcmp(avtype, AV_V_TYPE_TACPLUS))) {
	    if (avcomment)
		logmsg("%s %s: %s [%s] (%s)", avtype, avresult, avuser, avipaddr, avcomment);
	    else
		logmsg("%s %s: %s [%s]", avtype, avresult, avuser, avipaddr);
	}
    }
    return MAVIS_FINAL;
}

#include "mavis_glue.c"

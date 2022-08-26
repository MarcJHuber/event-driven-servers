/*
 * h_feat.c
 *
 * (C)1999-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

/*
 * FEAT may occur before the user has logged in, and the client is free to
 * assume that the features returned are complete, so we may not generate
 * the supported feature list dynamically. To quote from RFC2389:
 *
 * "..., when a client receives a FEAT response from an FTP server, it can
 * assume that the only extensions the server supports are those that are
 * listed in the FEAT response."
 */

#define __H_FEAT_C__
#include "headers.h"

#include "misc/tokenize.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

extern rb_tree_t *mimetypes;

void h_feat(struct context *ctx, char *arg __attribute__((unused)))
{
    struct list_struct *mfs = MLST_fact;
    struct md_method *m;
    char **l = lang;
    u_int i = 0;
    static int idx_host = -1;
    static int idx_rang = -1;
    static int idx_rest = -1;
    DebugIn(DEBUG_PROC);

    if (idx_host < 0)
	idx_host = get_request_index(requests, "host");

    if (idx_rang < 0)
	idx_rang = get_request_index(requests, "rang");

    if (idx_rest < 0)
	idx_rest = get_request_index(requests, "rest");

    reply(ctx, MSG_211_Extensions);

#ifdef WITH_SSL
    if (ssl_ctx)
	reply(ctx, " AUTH TLS\r\n");
#endif				/* WITH_SSL */

    reply(ctx, " ESTA\r\n");

    if (SET64_ISSET(idx_host, ctx->requests))
	reply(ctx, " HOST\r\n");

    if (SET64_ISSET(idx_rang, ctx->requests))
	reply(ctx, " RANG STREAM\r\n");

    reply(ctx, " LANG ");
    for (; *l; i++, l++) {
	reply(ctx, *l);
	if (ctx->lang == i)
	    reply(ctx, "*");
	reply(ctx, ";");
    }
    reply(ctx, "\r\n");

    reply(ctx, " MDTM\r\n");
    reply(ctx, " MFF Modify;UNIX.mode;UNIX.group;\r\n");
    reply(ctx, " MFMT\r\n");
    reply(ctx, " MLST ");
    for (; mfs->fact; mfs++)
	if ((mfs->flag != MLST_fact_mediatype || mimetypes)) {
	    reply(ctx, mfs->fact);
	    if (mfs->flag & ctx->mlst_facts)
		reply(ctx, "*");
	    reply(ctx, ";");
	}
    reply(ctx, "\r\n");

#ifdef WITH_ZLIB
    reply(ctx, " MODE Z\r\n");
#endif

    replyf(ctx, " HASH ");
    for (m = md_methods; m; m = m->next) {
	reply(ctx, m->ftp_name);
	if (m == ctx->md_method_hash)
	    reply(ctx, "*");
	if (m->next)
	    reply(ctx, ";");
    }
    reply(ctx, "\r\n");

#ifdef WITH_SSL
    if (ssl_ctx) {
	reply(ctx, " PBSZ\r\n");
	reply(ctx, " PROT\r\n");
    }
#endif				/* WITH_SSL */

    if (SET64_ISSET(idx_rest, ctx->requests))
	reply(ctx, " REST STREAM\r\n");
    reply(ctx, " SIZE\r\n");
    reply(ctx, " TVFS\r\n");
    reply(ctx, " UTF8\r\n");
    reply(ctx, MSG_211_End);

    DebugOut(DEBUG_PROC);
}

void h_opts(struct context *ctx, char *arg)
{
    char *t = arg;
    DebugIn(DEBUG_PROC);
    for (; *t && !isspace((int) *t); t++);
    if (*t)
	*t++ = 0;
    if (!strcasecmp(arg, "MLST")) {
	struct list_struct *mfs;
	char *u;
	ctx->mlst_facts = 0;
	for (; (u = strtok(t, ";")); t = NULL)
	    if (*u) {
		for (mfs = MLST_fact; mfs->fact && strcasecmp(mfs->fact, u); mfs++);
		if (mfs->fact)
		    ctx->mlst_facts |= mfs->flag;
	    }
	reply(ctx, MSG_200_Done);
    }
#ifdef WITH_ZLIB
    else if (!strcasecmp(arg, "MODE") && ctx->transfer_in_progress)
	reply(ctx, MSG_501_Transfer_in_progress);
    else if (!strcasecmp(arg, "MODE")) {
#ifndef MAXTOKENS
#define MAXTOKENS 32
#endif
	char *argv[MAXTOKENS];
	char **a = argv;
	int argc = tokenize(t, argv, MAXTOKENS);
	if (argc > 0) {
	    int level = ctx->deflate_level;
	    u_int extra = ctx->deflate_extra;
	    if (strcasecmp(argv[0], "z")) {
		reply(ctx, MSG_501_Unknown_transfer_mode);
		goto bye;
	    }
	    a++, argc--;
	    while (argc > 1) {
		struct list_struct *ls = mode_z_opt;
		while (ls->fact && strcasecmp(a[0], ls->fact))
		    ls++;
		switch (ls->flag) {
		case MODE_Z_ENGINE:
		    if (strcasecmp(a[1], "zlib")) {
			replyf(ctx, MSG_501_mode_z_error, a[0], " ", a[1]);
			goto bye;
		    }
		    break;
		case MODE_Z_METHOD:
		    if (atoi(a[1]) != Z_DEFLATED) {
			replyf(ctx, MSG_501_mode_z_error, a[0], " ", a[1]);
			goto bye;
		    }
		    break;
		case MODE_Z_LEVEL:
		    level = atoi(a[1]);
		    if (level < ctx->deflate_level_min)
			level = ctx->deflate_level_min;
		    if (level > ctx->deflate_level_max)
			level = ctx->deflate_level_max;
		    break;
		case MODE_Z_EXTRA:
		    if (strcasecmp(a[1], "on"))
			extra = 0;
		    else
			extra = 1;
		    break;
		default:
		    replyf(ctx, MSG_501_mode_z_error, a[0], "", a[1]);
		}
		argc -= 2, a += 2;
	    }
	    if (argc > 0)
		replyf(ctx, MSG_501_mode_z_error, a[0], "", "");
	    else {
		ctx->deflate_level = level;
		ctx->deflate_extra = extra;
		reply(ctx, MSG_200_Done);
	    }
	} else
	    reply(ctx, MSG_200_Done);
    }
#endif				/* WITH_ZLIB */
    else if (!strcasecmp(arg, "HASH")) {
	if (*t) {
	    struct md_method *m = md_method_find(md_methods, t);
	    if (m)
		ctx->md_method_hash = m;
	    else {
		reply(ctx, MSG_501_unknown_checksum_algorithm);
		goto bye;
	    }

	}
	replyf(ctx, "200 %s\r\n", ctx->md_method_hash->ftp_name);
    } else
	reply(ctx, MSG_501_No_options);

  bye:

    DebugOut(DEBUG_PROC);
}

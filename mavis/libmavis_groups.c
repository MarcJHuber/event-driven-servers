/*
 * libmavis_groups.c
 * (C)2011-2022 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#define MAVIS_name "groups"

#include "misc/sysconf.h"
#include <stdio.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <grp.h>
#include <errno.h>
#include <unistd.h>
#include <dlfcn.h>
#include "misc/strops.h"
#include "misc/io.h"
#include "groups.h"
#include "misc/memops.h"
#include "debug.h"
#include "log.h"

#ifdef WITH_PCRE
#include <pcre.h>
#endif
#ifdef WITH_PCRE2
#include <pcre2.h>
#endif

#include <regex.h>

static const char rcsid[] __attribute__((used)) = "$Id$";


struct regex_list;

#define MAVIS_CTX_PRIVATE	int resolve_gid; \
				int resolve_gids; \
				struct regex_list *group_regex; \
				struct regex_list *groups_regex; \
				struct regex_list *memberof_regex; \
				struct gid_list *gid; \
				struct gid_list *gids;

#include "mavis.h"

struct regex_list {
    struct regex_list *next;
    int negate;
    enum token type;
    void *p;
};

struct gid_list {
    struct gid_list *next;
    int negate;
    gid_t gid_start;
    gid_t gid_end;
};

static void parse_filter_regex(struct sym *sym, struct regex_list **l)
{
    int negate = 0;

    if (sym->code == S_not) {
	negate = 1;
	sym_get(sym);
    }

    do {
	int errcode = 0;
	while (*l)
	    l = &(*l)->next;
	*l = Xcalloc(1, sizeof(struct regex_list));
	(*l)->negate = negate;
	if (sym->code == S_slash) {
#ifdef WITH_PCRE
	    int erroffset;
	    const char *errptr;
	    (*l)->type = S_slash;
	    (*l)->p = (void *)
		pcre_compile2(sym->buf, PCRE_MULTILINE | common_data.regex_pcre_flags, &errcode, &errptr, &erroffset, NULL);
	    if (!(*l)->p)
		parse_error(sym, "In PCRE expression /%s/ at offset %d: %s", sym->buf, erroffset, errptr);
#else
#ifdef WITH_PCRE2
	    PCRE2_SIZE erroffset;
	    (*l)->type = S_slash;
	    (*l)->p = (void *)
		pcre2_compile((PCRE2_SPTR8) sym->buf, PCRE2_ZERO_TERMINATED, PCRE2_MULTILINE | common_data.regex_pcre_flags, &errcode, &erroffset, NULL);
	    if (!(*l)->p) {
		PCRE2_UCHAR buffer[256];
		pcre2_get_error_message(errcode, buffer, sizeof(buffer));
		parse_error(sym, "In PCRE expression /%s/ at offset %d: %s", sym->buf, erroffset, buffer);
	    }
#else
	    parse_error(sym, "You're using PCRE syntax, but this binary wasn't compiled with PCRE support.");
#endif
#endif
	} else {
	    (*l)->type = S_regex;
	    (*l)->p = Xcalloc(1, sizeof(regex_t));
	    errcode = regcomp((regex_t *) (*l)->p, sym->buf, REG_EXTENDED | REG_NOSUB | REG_NEWLINE | common_data.regex_posix_flags);
	    if (errcode) {
		char e[160];
		regerror(errcode, (regex_t *) (*l)->p, e, sizeof(e));
		parse_error(sym, "In regular expression '%s': %s", sym->buf, e);
	    }
	}
	sym_get(sym);
    } while (parse_comma(sym));
}

static void parse_gid(struct sym *sym, struct gid_list **l)
{
    int negate = 0;
    if (sym->code == S_not) {
	negate = 1;
	sym_get(sym);
    }

    do {
	u_int gs, ge;
	while (*l)
	    l = &(*l)->next;
	*l = Xcalloc(1, sizeof(struct gid_list));
	(*l)->negate = negate;

	switch (sscanf(sym->buf, "%u-%u", &gs, &ge)) {
	case 1:
	    ge = gs;
	case 2:
	    break;
	default:
	    parse_error(sym, "Expected numeric GID or GID range, but got \"%s\"", sym->buf);
	}
	(*l)->gid_start = gs;
	(*l)->gid_end = ge;
	sym_get(sym);
    } while (parse_comma(sym));
}

#define HAVE_mavis_parse_in
static int mavis_parse_in(mavis_ctx * mcx, struct sym *sym)
{
    while (1) {
	switch (sym->code) {
	case S_script:
	    mavis_script_parse(mcx, sym);
	    continue;
	case S_resolve:
	    sym_get(sym);
	    switch (sym->code) {
	    case S_gid:
		// resolve gid = (yes|no)
		sym_get(sym);
		parse(sym, S_equal);
		mcx->resolve_gid = parse_bool(sym);
		continue;
	    case S_gids:
		// resolve gids = (yes|no)
		sym_get(sym);
		parse(sym, S_equal);
		mcx->resolve_gids = parse_bool(sym);
		continue;
	    default:
		parse_error_expect(sym, S_gid, S_gids, S_unknown);
	    }
	    continue;
	case S_group:
	    sym_get(sym);
	    parse(sym, S_filter);
	    sym->flag_parse_pcre = 1;
	    parse(sym, S_equal);
	    // group filter = [not] regex ...
	    parse_filter_regex(sym, &mcx->group_regex);
	    sym->flag_parse_pcre = 0;
	    continue;
	case S_groups:
	    sym_get(sym);
	    parse(sym, S_filter);
	    sym->flag_parse_pcre = 1;
	    parse(sym, S_equal);
	    // groups filter = [not] regex ...
	    parse_filter_regex(sym, &mcx->groups_regex);
	    sym->flag_parse_pcre = 0;
	    continue;
	case S_memberof:
	    sym_get(sym);
	    parse(sym, S_filter);
	    sym->flag_parse_pcre = 1;
	    parse(sym, S_equal);
	    // memberof filter = [not] regex ...
	    parse_filter_regex(sym, &mcx->memberof_regex);
	    sym->flag_parse_pcre = 0;
	    continue;
	case S_gid:
	    sym_get(sym);
	    parse(sym, S_filter);
	    parse(sym, S_equal);
	    // gid filter = [not] <gid>[-<gid>][,<gid>[-<gid>]]+
	    parse_gid(sym, &mcx->gid);
	    continue;
	case S_gids:
	    sym_get(sym);
	    parse(sym, S_filter);
	    parse(sym, S_equal);
	    // gids filter = [not] <gid>[-<gid>][,<gid>[-<gid>]]+
	    parse_gid(sym, &mcx->gids);
	    continue;
	case S_eof:
	case S_closebra:
	    return MAVIS_CONF_OK;
	case S_action:
	    mavis_module_parse_action(mcx, sym);
	    continue;
	default:
	    parse_error_expect(sym, S_resolve, S_script, S_group, S_groups, S_memberof, S_gid, S_gids, S_action, S_unknown);
	}
    }
}

static int good_gid(struct gid_list *l, u_long gid)
{
    if (!l)
	return -1;
    while (l) {
	int match = l->gid_start <= (gid_t) gid && l->gid_end >= (gid_t) gid;
	if (l->negate)
	    match = !match;
	if (match)
	    return match;
	l = l->next;
    }
    return 0;
}

static int rxmatch(void *v, char *s, enum token token)
{
#ifdef WITH_PCRE2
    int pcre_res = 0;
    pcre2_match_data *match_data = NULL;
#endif
    switch (token) {
    case S_slash:
#ifdef WITH_PCRE
	return -1 < pcre_exec((pcre *) v, NULL, s, strlen(s), 0, 0, NULL, 0);
#else
#ifdef WITH_PCRE2
	match_data = pcre2_match_data_create_from_pattern((pcre2_code *) v, NULL);
	pcre_res = pcre2_match((pcre2_code *) v, (PCRE2_SPTR8) s, PCRE2_ZERO_TERMINATED, 0, 0, match_data, NULL);
	if (pcre_res < 0 && pcre_res != PCRE2_ERROR_NOMATCH) {
	    report_cfg_error(LOG_INFO, ~0, "PCRE2 matching error: %d", pcre_res);
	}
	pcre2_match_data_free(match_data);
	return -1 < pcre_res;
#endif
#endif
    default:
	return !regexec((regex_t *) v, s, 0, NULL, 0);
    }
}

static int good_name(struct regex_list *l, char *s)
{
    if (!l)
	return -1;
    while (l) {
	int match = rxmatch(l->p, s, l->type);

	if (l->negate)
	    match = !match;
	if (match)
	    return match;
	l = l->next;
    }
    return 0;
}

#define HAVE_mavis_recv_out
static int mavis_recv_out(mavis_ctx * mcx, av_ctx ** ac)
{
    char *s = NULL;
    if (mcx->resolve_gid) {
	s = av_get(*ac, AV_A_GID);

	if (s) {
	    u_long u = strtoul(s, NULL, 10);
	    if (u || errno != EINVAL) {
		struct group *g;
		if (!good_gid(mcx->gid, u)) {
		    av_unset(*ac, AV_A_GID);
		} else {
		    g = getgrgid((gid_t) u);
		    if (g && good_name(mcx->group_regex, g->gr_name))
			av_set(*ac, AV_A_GID, g->gr_name);
		    else
			av_unset(*ac, AV_A_GID);
		}
	    } else
		av_unset(*ac, AV_A_GID);
	}
    }

    if (mcx->resolve_gids) {
	s = av_get(*ac, AV_A_GIDS);
	if (s) {
	    char b[8192];
	    char *p = b;
	    *p = 0;

	    while (*s)
		if (isdigit((int) *s)) {
		    u_long u = strtoul(s, &s, 10);
		    if (u || errno != EINVAL) {
			struct group *g;
			if (!good_gid(mcx->gids, u))
			    continue;
			g = getgrgid((gid_t) u);
			if (g && good_name(mcx->groups_regex, g->gr_name)) {
			    ssize_t l;
			    l = strlen(g->gr_name);
			    if (b + sizeof(b) - p - 2 > l) {
				if (b[0])
				    *p++ = ',';
				strcpy(p, g->gr_name);
				p += l;
			    }
			}
		    }
		} else
		    s++;

	    if (b[0])
		av_set(*ac, AV_A_GIDS, b);
	    else
		av_unset(*ac, AV_A_GIDS);
	}
    }

    s = av_get(*ac, AV_A_TACMEMBER);
    if (s) {
	size_t len = strlen(s) + 1;
	char *v = alloca(len);
	char *b = alloca(len);
	char *p = b;
	*p = 0;
	memcpy(v, s, len);
	while (*v) {
	    char *e;
	    int quoted = (*v == '"');
	    if (quoted) {
		v++;
		for (e = v; *e && *e != '"'; e++);
		*e++ = 0;
		if (*e == ',')
		    e++;
		else if (*e)
		    break;
	    } else {
		for (e = v; *e && *e != ','; e++);
		if (*e)
		    *e++ = 0;
	    }
	    if (good_name(mcx->groups_regex, v)) {
		if (*b)
		    *p++ = ',';
		if (quoted)
		    *p++ = '"';
		len = strlen(v);
		memcpy(p, v, len);
		p += len;
		if (quoted)
		    *p++ = '"';
		*p = 0;
	    }
	    v = e;
	}
	if (b[0])
	    av_set(*ac, AV_A_TACMEMBER, b);
	else
	    av_unset(*ac, AV_A_TACMEMBER);
    }

    s = av_get(*ac, AV_A_MEMBEROF);
    if (s) {
	size_t len = strlen(s) + 1;
	char *v = alloca(len);
	char *b = alloca(len);
	char *p = b;
	*p = 0;
	memcpy(v, s, len);
	while (*v) {
	    char *e;
	    if (*v != '"')
		break;
	    v++;
	    for (e = v; *e && *e != '"'; e++);
	    if (*e != '"')
		break;
	    *e++ = 0;
	    if (*e == ',')
		e++;
	    if (good_name(mcx->memberof_regex, v)) {
		if (*b)
		    *p++ = ',';
		*p++ = '"';
		len = strlen(v);
		memcpy(p, v, len);
		p += len;
		*p++ = '"';
		*p = 0;
	    }
	    v = e;
	}
	if (b[0])
	    av_set(*ac, AV_A_MEMBEROF, b);
	else
	    av_unset(*ac, AV_A_MEMBEROF);
    }

    return MAVIS_FINAL;
}

static void drop_gr(struct regex_list *r)
{
    while (r) {
	struct regex_list *l = r->next;
#ifdef WITH_PCRE
	if (r->type == S_slash)
	    pcre_free(r->p);
	else
#else
#ifdef WITH_PCRE2
	if (r->type == S_slash)
	    pcre2_code_free(r->p);
	else
#endif
#endif
	    regfree(r->p);

	free(r);
	r = l;
    }
}

static void drop_gl(struct gid_list *r)
{
    while (r) {
	struct gid_list *l = r->next;
	free(r);
	r = l;
    }
}

#define HAVE_mavis_drop_in
static void mavis_drop_in(mavis_ctx * mcx)
{
    drop_gr(mcx->group_regex);
    drop_gr(mcx->groups_regex);
    drop_gl(mcx->gid);
    drop_gl(mcx->gids);
}

#include "mavis_glue.c"

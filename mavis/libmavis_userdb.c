/*
 * libmavis_userdb.c
 * (C)1998-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#define MAVIS_name "userdb"

#include "misc/sysconf.h"
#include "misc/strops.h"
#include "misc/memops.h"
#include "misc/io.h"
#include "debug.h"
#include "misc/rb.h"
#include "misc/md5crypt.h"
#include <unistd.h>
#include <fcntl.h>
#include <grp.h>
#include <dlfcn.h>

static const char rcsid[] __attribute__((used)) = "$Id$";

#define MAVIS_CTX_PRIVATE	\
	rb_tree_t *usertable;

#include "mavis.h"

struct user {
    char *name;
    char *passwd;
    enum token passwd_type;
    av_ctx *ac;
};

/*
user = name { ... }
*/
#define HAVE_mavis_parse_in
static int mavis_parse_in(mavis_ctx * mcx, struct sym *sym)
{
    struct user *u;
    char *t;

    while (1) {
	switch (sym->code) {
	case S_script:
	    mavis_script_parse(mcx, sym);
	    continue;
	case S_user:
	    sym_get(sym);
	    parse(sym, S_equal);
	    u = calloc(1, sizeof(struct user));
	    u->name = sym->buf;
	    if (RB_lookup(mcx->usertable, (void *) u)) {
		parse_error(sym, "user '%s' already defined.", sym->buf);
	    }
	    u->name = strdup(sym->buf);
	    u->ac = av_new(NULL, NULL);
	    sym_get(sym);
	    parse(sym, S_openbra);
	    while (sym->code != S_eof && sym->code != S_closebra) {
		switch (sym->code) {
		case S_password:
		    sym_get(sym);
		    parse(sym, S_equal);
		    switch (sym->code) {
		    case S_mavis:
		    case S_clear:
		    case S_crypt:
			break;
		    default:
			parse_error_expect(sym, S_clear, S_crypt, S_mavis, S_unknown);
		    }
		    u->passwd_type = sym->code;
		    sym_get(sym);
		    if (u->passwd_type != S_mavis) {
			strset(&u->passwd, sym->buf);
			sym_get(sym);
		    }
		    break;
		case S_userid:
		    sym_get(sym);
		    parse(sym, S_equal);
		    av_set(u->ac, AV_A_UID, sym->buf);
		    sym_get(sym);
		    break;
		case S_groupid:
		    sym_get(sym);
		    parse(sym, S_equal);
		    av_set(u->ac, AV_A_GIDS, sym->buf);
		    t = strchr(sym->buf, ',');
		    if (t)
			*t = 0;
		    av_set(u->ac, AV_A_GID, sym->buf);
		    sym_get(sym);
		    break;
		case S_cert:
		    sym_get(sym);
		    parse(sym, S_subject);
		    parse(sym, S_equal);
		    av_set(u->ac, AV_A_CERTSUBJ, sym->buf);
		    sym_get(sym);
		    break;
		case S_root:
		    sym_get(sym);
		    parse(sym, S_equal);
		    av_set(u->ac, AV_A_ROOT, sym->buf);
		    sym_get(sym);
		    break;
		case S_home:
		    sym_get(sym);
		    parse(sym, S_equal);
		    av_set(u->ac, AV_A_HOME, sym->buf);
		    sym_get(sym);
		    break;
		case S_set:
		    {
			int attr;
			sym_get(sym);
			attr = av_attribute_to_i(sym->buf);
			if (attr < 0)
			    parse_error(sym, "Unknown attribute '%s'", sym->buf);
			sym_get(sym);
			parse(sym, S_equal);
			av_set(u->ac, attr, sym->buf);
			sym_get(sym);
			break;
		    }
		default:
		    parse_error_expect(sym, S_script, S_password, S_userid, S_groupid, S_cert, S_root, S_home, S_unknown);
		}
	    }
	    parse(sym, S_closebra);
	    RB_insert(mcx->usertable, u);
	    continue;
	case S_eof:
	case S_closebra:
	    return MAVIS_CONF_OK;
	default:
	    parse_error_expect(sym, S_user, S_closebra, S_unknown);
	}
    }
}

#define HAVE_mavis_drop_in
static void mavis_drop_in(mavis_ctx * mcx)
{
    RB_tree_delete(mcx->usertable);
}

#define HAVE_mavis_send_in
static int mavis_send_in(mavis_ctx * mcx, av_ctx ** ac)
{
    char *t, *m, *p;
    struct user *u = alloca(sizeof(struct user));

    t = av_get(*ac, AV_A_TYPE);

    if (strcmp(t, AV_V_TYPE_FTP))
	return MAVIS_DOWN;

    m = av_get(*ac, AV_A_FTP_ANONYMOUS);
    if (m && !strcmp(m, AV_V_BOOL_TRUE))
	return MAVIS_DOWN;

    u->name = av_get(*ac, AV_A_USER);

    u = (struct user *) RB_lookup(mcx->usertable, (void *) u);
    if (!u || u->passwd_type == S_mavis)
	return MAVIS_DOWN;

    p = av_get(*ac, AV_A_PASSWORD);

    if (u->passwd_type == S_clear)
	av_set(*ac, AV_A_DBPASSWORD, u->passwd);
    else if (!strncmp(u->passwd, "$1$", 3)) {
	if (!strcmp(u->passwd, md5crypt(p, u->passwd)))
	    av_set(*ac, AV_A_DBPASSWORD, p);
    } else if (!strcmp(u->passwd, crypt(p, u->passwd)))
	av_set(*ac, AV_A_DBPASSWORD, p);

    av_merge(*ac, u->ac);

    return MAVIS_FINAL;
}

#define HAVE_mavis_recv_out
static int mavis_recv_out(mavis_ctx * mcx, av_ctx ** ac)
{
    char *t, *m;
    struct user *u = alloca(sizeof(struct user));

    t = av_get(*ac, AV_A_TYPE);

    if (strcmp(t, AV_V_TYPE_FTP))
	return MAVIS_DOWN;

    m = av_get(*ac, AV_A_FTP_ANONYMOUS);
    if (m && !strcmp(m, AV_V_BOOL_TRUE))
	return MAVIS_DOWN;

    u->name = av_get(*ac, AV_A_USER);

    u = (struct user *) RB_lookup(mcx->usertable, (void *) u);
    if (!u || u->passwd_type != S_mavis)
	return MAVIS_DOWN;

    av_merge(*ac, u->ac);

    return MAVIS_FINAL;
}

static int compare_user(const void *a, const void *b)
{
    return strcmp(((struct user *) a)->name, ((struct user *) b)->name);
}

static void free_user(struct user *user)
{
    Xfree(&user->name);
    Xfree(&user->passwd);
    av_free(user->ac);
    free(user);
}

#define HAVE_mavis_new
static void mavis_new(mavis_ctx * mcx)
{
    mcx->usertable = RB_tree_new(compare_user, (void (*)(void *)) free_user);
}

#include "mavis_glue.c"

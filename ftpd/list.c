/*
 * list.c
 *
 * (C)1998-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include "headers.h"
#include "glob.h"
#include "misc/rb.h"
#include "misc/tokenize.h"
#include <pwd.h>
#include <grp.h>

static const char rcsid[] __attribute__((used)) = "$Id$";

static int list_dir(struct context *, char *, char *);
static void list_dir_details(struct context *, int);

#define list_basename(A) ((strlen (A) <= ctx->rootlen) ? "/" : basename (A))

rb_tree_t *mimetypes = NULL;

struct mime_type {
    char *extension;
    char mimetype[1];
};

static int compare_extension(const void *a, const void *b)
{
    return strcasecmp(((struct mime_type *) a)->extension, ((struct mime_type *) b)->extension);
}

static void free_payload(void *payload)
{
    free(payload);
}

static char *lookup_mimetype(char *name)
{
    char *e = strrchr(name, '.');
    if (e) {
	rb_node_t *rb;
	static struct mime_type *mt_last = NULL;
	struct mime_type mt;

	if (mt_last && !strcasecmp(e, mt_last->extension))
	    return mt_last->mimetype;

	mt.extension = e + 1;
	if ((rb = RB_search(mimetypes, &mt))) {
	    mt_last = RB_payload(rb, struct mime_type *);
	    return mt_last->mimetype;
	}
    }
    return NULL;
}

void read_mimetypes(char *file)
{
    char inbuf[8000];
    size_t offset = 0;
    ssize_t inlength;
    char *linestart = inbuf;
    char *lineend;

    int fn = open(file, O_RDONLY);
    if (fn < 0) {
	logerr("open (%s)", file);
	return;
    }

    while ((inlength = read(fn, inbuf + offset, sizeof(inbuf) - 1 - offset)) > 0) {
	inlength += offset;
	inbuf[inlength] = 0;
	linestart = inbuf;

	while ((lineend = strchr(linestart, '\n'))) {
#define VECTOR_SIZE 99
	    char *vector[VECTOR_SIZE];
	    char **a = vector;
	    *lineend = 0;

	    tokenize(linestart, vector, VECTOR_SIZE);

	    if (*a && **a != '#' && strchr(*a, '/')) {
		char *mt = *a++;
		ssize_t mtlen = strlen(mt);
		for (; *a; a++) {
		    struct mime_type *keyval;
		    if (!mimetypes)
			mimetypes = RB_tree_new(compare_extension, free_payload);
		    keyval = Xcalloc(1, sizeof(struct mime_type) + 1 + strlen(*a) + mtlen);
		    strcpy(keyval->mimetype, mt);
		    keyval->extension = keyval->mimetype + mtlen + 1;
		    strcpy(keyval->extension, *a);
		    RB_search_and_delete(mimetypes, keyval);
		    RB_insert(mimetypes, keyval);
		}
	    }
	    linestart = lineend + 1;
	}

	offset = inbuf + inlength - linestart;
	if (offset)
	    memmove(inbuf, linestart, offset);
    }
    close(fn);
}

int check_gids(struct context *ctx, gid_t gid)
{
    int i;
    for (i = 0; i < ctx->gids_size; i++)
	if (gid == ctx->gids[i])
	    return -1;
    return 0;
}

struct id_item {
    int id;
    char name[1];
};

static int compare_id(const void *a, const void *b)
{
    return (((struct id_item *) a)->id - ((struct id_item *) b)->id);
}

char *lookup_uid(struct context *ctx, uid_t uid)
{
    struct passwd *pw;
    char *u = NULL;
    static rb_tree_t *cache = NULL;
    static uid_t last_uid;
    static char *last_user = NULL;
    rb_node_t *t;
    struct id_item idi, *i;

    if (!ctx->resolve_ids)
	return ctx->ftpuser;

    if (!cache) {
	cache = RB_tree_new(compare_id, free_payload);
	setpwent();
	while ((pw = getpwent()))
	    if (pw->pw_name) {
		i = Xcalloc(1, sizeof(struct id_item) + strlen(pw->pw_name));
		i->id = pw->pw_uid;
		strcpy(i->name, pw->pw_name);
		RB_insert(cache, i);
	    }
	endpwent();
    }

    if (uid == last_uid && last_user)
	return last_user;

    idi.id = uid;

    if ((t = RB_search(cache, &idi)))
	u = RB_payload(t, struct id_item *)->name;
    else {
	pw = getpwuid(uid);
	if (pw && pw->pw_name)
	    u = pw->pw_name;
	if (!u)
	    u = ctx->ftpuser;

	i = Xcalloc(1, sizeof(struct id_item) + strlen(u));
	i->id = uid;
	strcpy(i->name, u);
	RB_insert(cache, i);
    }
    last_user = u, last_uid = uid;
    return u;
}

char *lookup_gid(struct context *ctx, gid_t gid)
{
    struct group *gr;
    char *g = NULL;
    static rb_tree_t *cache = NULL;
    static uid_t last_gid;
    static char *last_group = NULL;
    rb_node_t *t;
    struct id_item idi, *i;

    if (!ctx->resolve_ids)
	return ctx->ftpgroup;

    if (!cache) {
	cache = RB_tree_new(compare_id, free_payload);
	setgrent();
	while ((gr = getgrent()))
	    if (gr->gr_name) {
		i = Xcalloc(1, sizeof(struct id_item) + strlen(gr->gr_name));
		i->id = gr->gr_gid;
		strcpy(i->name, gr->gr_name);
		RB_insert(cache, i);
	    }
	endgrent();
    }

    if (gid == last_gid && last_group)
	return last_group;

    idi.id = gid;

    if ((t = RB_search(cache, &idi)))
	g = RB_payload(t, struct id_item *)->name;
    else {
	gr = getgrgid(gid);
	if (gr && gr->gr_name)
	    g = gr->gr_name;
	if (!g)
	    g = ctx->ftpgroup;

	i = Xcalloc(1, sizeof(struct id_item) + strlen(g));
	i->id = gid;
	strcpy(i->name, g);
	RB_insert(cache, i);
    }
    last_group = g, last_gid = gid;
    return g;
}

static char *permtable = NULL;

static char *init_permtable(void)
{
    int i;
    char *pt[] = { "---", "--x", "-w-", "-wx", "r--", "r-x", "rw-", "rwx" };
    char *p;

    permtable = Xcalloc(5120, 1);

    for (p = permtable, i = 0; i < 512; i++, p += 10)
	sprintf(p, "%s%s%s", pt[i >> 6], pt[7 & (i >> 3)], pt[7 & i]);

    return permtable;
}

static char *list_one(struct context *ctx, char *filename, enum list_mode mode, char *buffer, size_t buflen)
{
    int l;
    struct stat st;
    char *t = buffer;

    Debug((DEBUG_PROC, "+ %s(\"%s\", ...\n", __func__, filename));

    if (pickystat(ctx, &st, filename)) {
	DebugOut(DEBUG_PROC);
	return NULL;
    }

    buffer[0] = 0;

    switch (mode) {
    case List_list:
	if (!permtable)
	    init_permtable();

	l = snprintf(buffer, buflen,
		     "%c%s %4lu %-8s %-8s %8llu ",
		     S_ISDIR(st.st_mode) ? 'd' : '-',
		     permtable + 10 * (st.st_mode & 0777),
		     (u_long) st.st_nlink, lookup_uid(ctx, st.st_uid), lookup_gid(ctx, st.st_gid), (unsigned long long) st.st_size);
	strftime(buffer + l, buflen - l, (st.st_mtime + 15552000 < io_now.tv_sec)
		 ? "%b %e  %Y " : "%b %e %H:%M ", localtime(&st.st_mtime));
	break;
    case List_mlsd:
	if (!(ctx->mlst_facts & MLST_fact_type) && filename[0] == '.' && (!filename[1] || (filename[1] == '.' && !filename[2])))
	    break;
    case List_mlst:
	if (ctx->mlst_facts & MLST_fact_type) {
	    *t++ = 'T';
	    *t++ = 'y';
	    *t++ = 'p';
	    *t++ = 'e';
	    *t++ = '=';
	    if (S_ISDIR(st.st_mode)) {
		if (filename[0] == '.') {
		    if (filename[1] == '.' && !filename[2])
			*t++ = 'p';
		    else if (!filename[1])
			*t++ = 'c';
		}
		*t++ = 'd';
		*t++ = 'i';
		*t++ = 'r';
	    } else {
		*t++ = 'f';
		*t++ = 'i';
		*t++ = 'l';
		*t++ = 'e';
	    }
	    *t++ = ';';
	}

	if (ctx->mlst_facts & MLST_fact_size && !S_ISDIR(st.st_mode))
	    t += snprintf(t, (size_t) (buffer + buflen - t), "Size=%llu;", (unsigned long long) st.st_size);

	if (ctx->mlst_facts & MLST_fact_modify)
	    t += strftime(t, 30, "Modify=%Y%m%d%H%M%S;", gmtime(&st.st_mtime));

	if (ctx->mlst_facts & MLST_fact_change)
	    t += strftime(t, 30, "Change=%Y%m%d%H%M%S;", gmtime(&st.st_ctime));

	if (ctx->mlst_facts & MLST_fact_unique) {
	    char table[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" "abcdefghijklmnopqrstuvwxyz0123456789+/";

	    u_long l1 = (u_long) st.st_dev;
	    u_long l2 = (u_long) st.st_ino;

	    *t++ = 'U';
	    *t++ = 'n';
	    *t++ = 'i';
	    *t++ = 'q';
	    *t++ = 'u';
	    *t++ = 'e';
	    *t++ = '=';

	    do
		*t++ = table[l1 & 0x3F];
	    while (l1 >>= 6);
	    *t++ = '.';

	    do
		*t++ = table[l2 & 0x3F];
	    while (l2 >>= 6);
	    *t++ = ';';
	}

	if (ctx->mlst_facts & MLST_fact_perm) {
	    *t++ = 'P';
	    *t++ = 'e';
	    *t++ = 'r';
	    *t++ = 'm';
	    *t++ = '=';

	    if (!S_ISDIR(st.st_mode) && !ctx->anonymous && (ctx->uid == st.st_uid) && (S_IWUSR & st.st_mode))
		*t++ = 'a';	/* APPE may be applied */

	    if (S_ISDIR(st.st_mode)) {
		if (ctx->anonymous) {
		    if (check_incoming(ctx, filename, 077)) {
			*t++ = 'c';	/* file creation should succeed */
			*t++ = 'm';	/* directory creation should succeed */
		    }
		} else {
		    if ((ctx->uid == st.st_uid) && (S_IWUSR & st.st_mode)) {
			*t++ = 'c';	/* file creation should succeed */
			*t++ = 'm';	/* directory creation should succeed */
			*t++ = 'p';	/* directory contents may be removed */
		    }
		}
	    }

	    if (!ctx->anonymous && ctx->uid == st.st_uid &&
		(!ctx->pst_valid ||
		 (ctx->pst.st_mode & S_IWUSR) || (ctx->pst.st_mode & S_IWGRP && check_gids(ctx, ctx->pst.st_gid)) || (ctx->pst.st_mode & S_IWOTH))) {
		*t++ = 'd';	/* rename should succeed */
		*t++ = 'f';	/* delete should succeed */
	    }

	    if (S_ISDIR(st.st_mode) && ((ctx->uid == st.st_uid) || (S_IXGRP & st.st_mode && check_gids(ctx, st.st_gid)) || (S_IXOTH & st.st_mode))) {
		*t++ = 'e';	/* cwd should succeed */
		*t++ = 'l';	/* list command may be applied */
	    }

	    if (!S_ISDIR(st.st_mode) && ((ctx->uid == st.st_uid) || (S_IRGRP & st.st_mode && check_gids(ctx, st.st_gid)) || (S_IROTH & st.st_mode)))
		*t++ = 'r';	/* RETR command may be applied */

	    if (!S_ISDIR(st.st_mode) && !ctx->anonymous)
		*t++ = 'w';	/* STOR command may be applied */

	    *t++ = ';';
	}

	if (!S_ISDIR(st.st_mode) && (ctx->mlst_facts & MLST_fact_mediatype && mimetypes)) {
	    char *mt = lookup_mimetype(filename);
	    if (mt)
		t += snprintf(t, (size_t) (buffer + buflen - t), "Media-Type=%s;", mt);
	}

	if (ctx->mlst_facts & MLST_fact_UNIX_mode)
	    t += snprintf(t, (size_t) (buffer + buflen - t), "UNIX.mode=%o;", 0777 & (u_int) st.st_mode);

	if (ctx->mlst_facts & MLST_fact_UNIX_owner)
	    t += snprintf(t, (size_t) (buffer + buflen - t), "UNIX.owner=%s;", lookup_uid(ctx, st.st_uid));

	if (ctx->mlst_facts & MLST_fact_UNIX_group)
	    t += snprintf(t, (size_t) (buffer + buflen - t), "UNIX.group=%s;", lookup_gid(ctx, st.st_gid));
	*t++ = ' ';
	*t = 0;

	break;
    case List_nlst:
	if (nlst_files_only && !S_ISREG(st.st_mode))
	    return NULL;
    default:
	buffer[0] = 0;
    }

    DebugOut(DEBUG_PROC);
    return buffer;
}

void list_stat(struct context *ctx, char *path)
{
    char *t, *u;

    DebugIn(DEBUG_PROC);

    ctx->list_to_cc = 1;
    ctx->list_mode = List_list;
    ctx->stat_reply = MSG_550_No_such_file_or_directory;

    if ((t = buildpath(ctx, (path && *path) ? path : "."))) {
	char buffer[1024];
	if (!list_dir(ctx, t, NULL)) {
	    replyf(ctx, MSG_212_status_of, path);
	    ctx->stat_reply = MSG_212_status_end;
	    io_sched_add(ctx->io, ctx, (void *) list_dir_details, 0, 0);
	    io_clr_o(ctx->io, ctx->cfn);
	} else if ((u = list_one(ctx, t, List_list, buffer, sizeof(buffer)))) {
	    replyf(ctx, MSG_213_status_of, path);
	    ctx->stat_reply = MSG_213_status_end;
	    replyf(ctx, "%s%s\r\n", u, list_basename(t));
	} else if (path && !strchr(path, '/')
		   && !list_dir(ctx, ctx->cwd, path)) {
	    replyf(ctx, MSG_212_status_of, path);
	    ctx->stat_reply = MSG_212_status_end;
	    io_sched_add(ctx->io, ctx, (void *) list_dir_details, 0, 0);
	    io_clr_o(ctx->io, ctx->cfn);
	}
    }
    DebugOut(DEBUG_PROC);
}

void h_mlst(struct context *ctx, char *path)
{
    char *t, *u, buffer[1024];

    DebugIn(DEBUG_PROC);

    t = buildpath(ctx, (path && *path) ? path : ".");

    if (t) {
	char *v = strrchr(t, '/');

	ctx->pst_valid = 0;

	if (v) {
	    *v = 0;
	    if (!pickystat(ctx, &ctx->pst, t))
		ctx->pst_valid = 1;
	}

	if ((u = list_one(ctx, t, List_mlst, buffer, sizeof(buffer)))) {
	    replyf(ctx, MSG_250_listing_start, t[ctx->rootlen] ? t + ctx->rootlen : "/");
	    replyf(ctx, " %s%s\r\n", u, t[ctx->rootlen] ? t + ctx->rootlen : "/");
	    reply(ctx, MSG_250_listing_end);
	}

	ctx->pst_valid = 0;

    } else
	reply(ctx, MSG_501_No_such_file_or_directory);

    DebugOut(DEBUG_PROC);
}

void list(struct context *ctx, char *path, enum list_mode mode)
{
    char *t, *u;

    DebugIn(DEBUG_PROC);

    ctx->list_to_cc = 0;
    ctx->buffer_filled = 1;
    ctx->list_mode = mode;

    if ((t = buildpath(ctx, (path && *path) ? path : ".")))
	switch (list_dir(ctx, t, NULL)) {
	case 0:
	    io_sched_add(ctx->io, ctx, (void *) list_dir_details, 0, 0);
	    io_clr_o(ctx->io, ctx->cfn);
	case EPERM:
	    break;
	default:
	    if (mode != List_mlsd) {
		char buffer[1024];

		/* t is a single file */
		if ((u = list_one(ctx, t, mode, buffer, sizeof(buffer)))) {
		    if (mode != List_nlst)
			ctx->dbufi = buffer_write(ctx->dbufi, u, strlen(u));
		    t = list_basename(t);
		    ctx->dbufi = buffer_write(ctx->dbufi, t, strlen(t));
		    ctx->dbufi = buffer_write(ctx->dbufi, "\r\n", 2);
		}
		/* Workaround for UNIX guys. And for broken clients. */
		else if (mode != List_mlsd && mode != List_mlst && path && !strchr(path, '/')) {
		    if (path[0] == '-')
			list(ctx, ".", List_list);
		    else if (!list_dir(ctx, ctx->cwd, path)) {
			io_sched_add(ctx->io, ctx, (void *) list_dir_details, 0, 0);
			io_clr_o(ctx->io, ctx->cfn);
		    }
		}
	    }
	}
    DebugOut(DEBUG_PROC);
}

/* list_dir() return values:
 *  0: OK, Caller should call list_dir_details ()
 *  EINVAL: filter is not a valid globbing expression
 *  EPERM: user has no access to directory
 *  ENOTDIR: dirname is not a directory
 *  ENOENT: dirname does not exist
 */

static int list_dir(struct context *ctx, char *dirname, char *filter)
{
    DIR *dir;
    struct dirent *de;
    struct glob_pattern *g = NULL;

    Debug((DEBUG_PROC, "+ %s(\"%s\", ...)\n", __func__, dirname));

    if (!dirname)
	dirname = ".";

    if (filter && !(g = glob_comp(filter))) {
	Debug((DEBUG_PROC, "- %s: glob_comp failed\n", __func__));
	return EINVAL;
    }

    ctx->pst_valid = 0;

    if (pickystat(ctx, &ctx->pst, dirname)) {
	DebugOut(DEBUG_PROC);
	return (errno == ENOENT ? ENOENT : EPERM);
    }

    ctx->pst_valid = 1;

    if (!(dir = opendir(dirname))) {
	Debug((DEBUG_PROC, "- %s: opendir failure\n", __func__));
	return (errno == ENOTDIR ? ENOTDIR : EPERM);
    }

    RB_tree_delete(ctx->filelist);
    ctx->filelist = RB_tree_new(NULL, free_payload);

    while ((de = readdir(dir))) {
	char *copy;
	if (de->d_name[0] == '.') {
	    if (de->d_name[1] == '.' && !de->d_name[2]) {
		/* don't display ".." in top level root directory */
		if (ctx->pst.st_ino == ctx->root_ino && ctx->pst.st_dev == ctx->root_dev)
		    continue;
	    } else if (!ctx->allow_dotfiles)
		continue;

	    /* wildcards my not match files starting with a dot */
	    if (filter && filter[0] != '.')
		continue;
	}

	if (filter && !glob_exec(g, de->d_name))
	    continue;

	copy = Xstrdup(de->d_name);
	RB_insert(ctx->filelist, copy);
	Debug((DEBUG_PROC, "inserted %s\n", copy));
    }

    if (g)
	glob_free(g);

    if (RB_empty(ctx->filelist)) {
	closedir(dir);
	Debug((DEBUG_PROC, "- %s: no files\n", __func__));
	return ENOENT;
    }
#ifdef WITH_DIRFD
    ctx->dirfn = dup(dirfd(dir));
    closedir(dir);
#else				/* WITH_DIRFD */
    closedir(dir);
    ctx->dirfn = open(dirname, O_RDONLY);
#endif				/* WITH_DIRFD */

    fcntl(ctx->dirfn, F_SETFD, FD_CLOEXEC);

    DebugOut(DEBUG_PROC);
    return 0;
}

static void list_dir_details(struct context *ctx, int cur __attribute__((unused)))
{
    rb_node_t *rbn;
    struct buffer *b;
    int i = 5;
    struct buffer *(*bf) (struct buffer *, char *, size_t);

    DebugIn(DEBUG_PROC);

    if ((ctx->uid != (uid_t) - 1) && (current_uid != ctx->uid || current_gid != ctx->gid || update_ids)) {
	UNUSED_RESULT(seteuid(0));
	setgroups(ctx->gids_size, ctx->gids);
	UNUSED_RESULT(setegid(ctx->gid));
	UNUSED_RESULT(seteuid(ctx->uid));
	current_gid = ctx->gid;
	current_uid = ctx->uid;
	update_ids = 0;
    }

    if (ctx->dirfn < 0 || fchdir(ctx->dirfn)) {
	RB_tree_delete(ctx->filelist);
	ctx->filelist = NULL;
	if (chdir("/")) {
	    // FIXME
	}
	DebugOut(DEBUG_PROC);
	return;
    }

    if (ctx->list_to_cc)
	b = ctx->cbufo, bf = buffer_reply;
    else
	b = ctx->dbufi, bf = buffer_write;

    while (i-- && (rbn = RB_first(ctx->filelist))) {
	char *u, buffer[1024];
	char *p;

	if ((u = list_one(ctx, p = RB_payload(rbn, char *), ctx->list_mode, buffer, sizeof(buffer))))
	    switch (ctx->list_mode) {
	    case List_mlsd:
	    case List_list:
		b = bf(b, u, strlen(u));
	    case List_nlst:
		b = bf(b, p, strlen(p));
		b = buffer_write(b, "\r\n", 2);
	    default:
		;
	    }
	RB_delete(ctx->filelist, rbn);
    }

    /*  Could use
     *     *(ctx->list_to_cc ? &ctx->cbufo : &ctx->dbufi) = b;
     *  instead of:
     */
    if (ctx->list_to_cc)
	ctx->cbufo = b;
    else
	ctx->dbufi = b;

    if (RB_empty(ctx->filelist)) {
	Debug((DEBUG_PROC, "filelist empty\n"));
	io_sched_pop(ctx->io, ctx);
	RB_tree_delete(ctx->filelist);
	ctx->filelist = NULL;
	close(ctx->dirfn);
	ctx->dirfn = -1;
	ctx->pst_valid = 0;
    } else
	io_sched_renew_proc(ctx->io, ctx, (void *) list_dir_details);

    if (chdir("/")) {
	//FIXME
    }

    DebugOut(DEBUG_PROC);
}

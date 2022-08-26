/*
 * h_site_checksum.c
 * (C)2000-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include "headers.h"
#include "misc/tohex.h"
#ifdef WITH_SSL
#include <openssl/evp.h>
#endif

static const char rcsid[] __attribute__((used)) = "$Id$";

static void md_crc32_update(struct context *ctx, u_char * s, size_t len)
{
    ctx->checksum.crc32 = crc32_update(ctx->checksum.crc32, s, len);
}

static void md_md5_update(struct context *ctx, u_char * s, size_t len)
{
    myMD5Update(&ctx->checksum.md5context, s, len);
}

#ifdef WITH_SSL
static void md_evp_update(struct context *ctx, u_char * s, size_t len)
{
    EVP_DigestUpdate(ctx->checksum.mdctx, s, len);
}
#endif

static char *md_crc32_final(struct context *ctx)
{
    static char res[20];
    snprintf(res, sizeof(res), "%u", crc32_final(ctx->checksum.crc32, ctx->offset));
    return res;
}

static char *md_md5_final(struct context *ctx)
{
    static char d[33];
    u_char md[16];
    myMD5Final(md, &ctx->checksum.md5context);
    tohex(md, 16, d);
    return d;
}

#ifdef WITH_SSL
static char *md_evp_final(struct context *ctx)
{
    static char d[2 * EVP_MAX_MD_SIZE + 1];
    u_int md_len;
    u_char md[EVP_MAX_MD_SIZE];
    EVP_DigestFinal(ctx->checksum.mdctx, md, &md_len);
    tohex((u_char *) md, md_len, d);
    return d;
}
#endif

static void md_crc32_init(struct context *ctx)
{
    ctx->checksum.crc32 = INITCRC32;
}

static void md_md5_init(struct context *ctx)
{
    myMD5Init(&ctx->checksum.md5context);
}

#ifdef WITH_SSL
static void md_evp_init(struct context *ctx)
{
    struct md_method *m = ctx->md_hash ? ctx->md_method_hash : ctx->md_method_checksum;
#if OPENSSL_VERSION_NUMBER < 0x10100000
    ctx->checksum.mdctx = EVP_MD_CTX_create();
#else
    ctx->checksum.mdctx = EVP_MD_CTX_new();
#endif
    EVP_MD_CTX_init(ctx->checksum.mdctx);
    EVP_DigestInit_ex(ctx->checksum.mdctx, m->md, NULL);
}
#endif

static void getchecksum(struct context *ctx)
{
    size_t len;
    struct md_method *m = ctx->md_hash ? ctx->md_method_hash : ctx->md_method_checksum;

    DebugIn(DEBUG_BUFFER);

    sigbus_cur = ctx->cfn;

    if (chunk_get(ctx, &ctx->io_offset)) {
	reply(ctx, MSG_451_Internal_error);
	goto bye;
    }

    if (chunk_remaining(ctx)) {
	len = MIN((size_t) bufsize, ctx->chunk_length);
	m->update(ctx, (u_char *) ctx->chunk_start, len);
	chunk_release(ctx, len);
    }

    if (chunk_remaining(ctx))
	io_sched_renew_proc(ctx->io, ctx, (void *) getchecksum);
    else {
	if (!strcmp(m->ftp_name, "CRC32")) {
	    if (ctx->md_hash) {
		replyf(ctx, "213 %s %llu-%llu %s %s\r\n", m->ftp_name,
		       (unsigned long long) ctx->io_offset_start, (unsigned long long) ctx->offset, m->final(ctx), ctx->filename + ctx->rootlen);
	    } else
		replyf(ctx, "200 %s %llu %s\r\n", m->final(ctx), (unsigned long long) ctx->offset, ctx->filename + ctx->rootlen);
	} else if (ctx->md_hash) {
	    replyf(ctx, "213 %s %llu-%llu %s %s\r\n", m->ftp_name,
		   (unsigned long long) ctx->io_offset_start, (unsigned long long) ctx->offset, m->final(ctx), ctx->filename + ctx->rootlen);
	} else
	    replyf(ctx, "200 %s  %s\r\n", m->final(ctx), ctx->filename + ctx->rootlen);
      bye:
	io_sched_pop(ctx->io, ctx);
	ctx->offset = 0;
	cleanup_file(ctx, ctx->ffn);
	ctx->dbufi = buffer_free_all(ctx->dbufi);
#ifdef WITH_SSL
#if OPENSSL_VERSION_NUMBER < 0x10100000
	EVP_MD_CTX_destroy(ctx->checksum.mdctx);
#else
	EVP_MD_CTX_free(ctx->checksum.mdctx);
#endif
#endif
    }

    DebugOut(DEBUG_BUFFER);
}

struct md_method *md_method_find(struct md_method *m, char *s)
{
    while (m && strcasecmp(s, m->ftp_name))
	m = m->next;
    return m;
}

void h_site_checkmethod(struct context *ctx, char *arg)
{
    Debug((DEBUG_COMMAND, "+ %s %s\n", __func__, arg ? arg : "(NULL)"));

    if (arg && *arg) {
	struct md_method *m = md_method_find(md_methods, arg);
	if (m) {
	    ctx->md_method_checksum = m;
	    replyf(ctx, MSG_200_Checkmethod_set, m->ftp_name);
	} else
	    reply(ctx, MSG_504_Unknown_checkmethod);
    } else
	replyf(ctx, MSG_200_Checkmethod, ctx->md_method_checksum->ftp_name);

    DebugOut(DEBUG_COMMAND);
}

static void checksum_start(struct context *ctx, char *arg)
{
    char *t;
    struct stat st;
    struct md_method *m = ctx->md_hash ? ctx->md_method_hash : ctx->md_method_checksum;

    DebugIn(DEBUG_COMMAND);

    if (!arg && ctx->filename[0]) {
	if (pickystat(ctx, &st, ctx->filename)) {
	    reply(ctx, MSG_550_No_such_file_or_directory);
	    DebugOut(DEBUG_COMMAND);
	    return;
	}
	t = ctx->filename;
    } else {
	if (!arg || !arg[0]) {
	    reply(ctx, MSG_501_Syntax_error_arg_req);
	    DebugOut(DEBUG_COMMAND);
	    return;
	}

	if (ctx->ffn > -1) {
	    reply(ctx, MSG_452_Command_not_during_transfers);
	    DebugOut(DEBUG_COMMAND);
	    return;
	}

	if (!((t = buildpath(ctx, arg)) && (!pickystat(ctx, &st, t)))) {
	    reply(ctx, MSG_550_No_such_file_or_directory);
	    DebugOut(DEBUG_COMMAND);
	    return;
	}
    }

    if (!S_ISREG(st.st_mode))
	reply(ctx, MSG_550_Not_plain_file);
    else if ((ctx->ffn = open(t, O_RDONLY | O_LARGEFILE)) > -1) {
	fcntl(ctx->ffn, F_SETFD, FD_CLOEXEC);
	if (t != ctx->filename)
	    strcpy(ctx->filename, t);
	m->init(ctx);

#ifdef WITH_MMAP
	if (use_mmap)
	    ctx->iomode = IOMODE_mmap;
	else
#endif				/* WITH_MMAP */
	    ctx->iomode = IOMODE_read, ctx->iomode_fixed = 1;

	io_sched_add(ctx->io, ctx, (void *) getchecksum, 0, 0);
	ctx->quota_update_on_close = 0;
	ctx->offset = ctx->io_offset;
	ctx->remaining = st.st_size;
	if ((ctx->io_offset_end != -1)
	    && (ctx->remaining > ctx->io_offset_end + 1))
	    ctx->remaining = ctx->io_offset_end + 1;
    } else
	reply(ctx, MSG_550_No_such_file_or_directory);

    DebugOut(DEBUG_COMMAND);
}

void h_site_checksum(struct context *ctx, char *arg)
{
    DebugIn(DEBUG_COMMAND);
    ctx->md_hash = 0;
    ctx->io_offset = ctx->io_offset_start = 0;
    ctx->io_offset_end = -1;
    checksum_start(ctx, arg);
    DebugOut(DEBUG_COMMAND);
}

void h_hash(struct context *ctx, char *arg)
{
    DebugIn(DEBUG_COMMAND);
    ctx->md_hash = 1;
    checksum_start(ctx, arg);
    DebugOut(DEBUG_COMMAND);
}

void md_method_add(struct md_method **m, char *ftp_name,
		   char *openssl_name, void (*init)(struct context *), void(*update)(struct context *, u_char *, size_t), char * (*final)(struct context *))
{

    if(!ftp_name)
	return;
    while (*m && strcmp((*m)->ftp_name, ftp_name))
	m = &(*m)->next;
    if (m && *m)
	return;
    *m = calloc(1, sizeof(struct md_method));
    (*m)->ftp_name = ftp_name;
    (*m)->openssl_name = openssl_name;
    (*m)->init = init;
    (*m)->update = update;
    (*m)->final = final;
}

#ifdef WITH_SSL
static char *openssl_md_name_to_ftp(char *in)
{
    char *s, *t = alloca(strlen(in) + 1);
    s = t;
    while (*in) {
	*s = tolower((int) *in);
	s++, in++;
    }
    *s = *in;

    if (strstr(t, "rsa"))
	return NULL;
    if (strstr(t, "dsa"))
	return NULL;
    if (!strncmp(t, "sha", 3)) {
	if (t[3]) {
	    char *out = calloc(1, 2 + strlen(t));
	    strcpy(out, "SHA-");
	    strcpy(out + 4, t + 3);
	    return out;
	}
	return "SHA";
    }
    if (!strcmp(t, "md5"))
	return "MD5";
    return NULL;
}

static void openssl_md_add(const OBJ_NAME * name, void *m)
{
    char *s = openssl_md_name_to_ftp((char *) name->name);
    if (s)
	md_method_add((struct md_method **) m, s, (char *) name->name, &md_evp_init, &md_evp_update, &md_evp_final);
}

static void openssl_md_init(struct md_method **m)
{
    OpenSSL_add_all_digests();
    OBJ_NAME_do_all_sorted(OBJ_NAME_TYPE_MD_METH, openssl_md_add, (void *) m);
}
#endif

void md_init(void)
{
#ifdef WITH_SSL
    struct md_method *m;
#endif
    md_method_add(&md_methods, "CRC32", "crc32", &md_crc32_init, &md_crc32_update, &md_crc32_final);
    md_method_add(&md_methods, "POSIX", "crc32", &md_crc32_init, &md_crc32_update, &md_crc32_final);
    md_method_add(&md_methods, "MD5", "md5", &md_md5_init, &md_md5_update, &md_md5_final);
    md_method_add(&md_methods, "RFC1321", "md5", &md_md5_init, &md_md5_update, &md_md5_final);
#ifdef WITH_SSL
    openssl_md_init(&md_methods);
    for (m = md_methods; m; m = m->next) {
	m->md = EVP_get_digestbyname(m->openssl_name);
	// This overrides the custom implementations:
	if (m->md) {
	    m->init = &md_evp_init;
	    m->update = &md_evp_update;
	    m->final = &md_evp_final;
	}
    }
#endif
}

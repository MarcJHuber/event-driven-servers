/*
 * libmavis.c
 * (C)1998-2011 by Marc Huber <Marc.Huber@web.de>
 *
 * $Id$
 *
 */

#define __MAVIS_MAIN__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <dlfcn.h>
#include <sysexits.h>
#include <ctype.h>
#include "misc/io_sched.h"
#include "misc/memops.h"
#include "misc/mymd5.h"
#include "log.h"
#include "misc/base64.h"
#include "debug.h"
#include "mavis.h"
#include "misc/version.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

int mavis_method_add(mavis_ctx ** mcx, struct io_context *ioctx, char *path, char *id)
{
    void *handle;
    void *(*mn)(void *, struct io_context *, char *);

    Debug((DEBUG_MAVIS, "+ %s(%s)\n", __func__, path));

    handle = dlopen(path, RTLD_LAZY | RTLD_GLOBAL);

    if (!handle) {
	Debug((DEBUG_MAVIS, "- %s(%s): dlopen failed.\n", __func__, path));
	return -1;
    }

    if (!(mn = (void *(*)(void *, struct io_context *, char *))
	  dlsym(handle, DLSYM_PREFIX "Mavis_new"))) {
	Debug((DEBUG_MAVIS, "- %s(%s): dlsym (%s) failed: %s\n", __func__, path, DLSYM_PREFIX "Mavis_new", dlerror()));
	return -1;
    }

    if (!*mcx) {
	*mcx = mn(handle, ioctx, id);
	(*mcx)->top = *mcx;
    } else
	(*mcx)->append(*mcx, mn(handle, ioctx, id));

    Debug((DEBUG_MAVIS, "- %s (OK)\n", __func__));
    return 0;
}

int mavis_init(mavis_ctx * mcx, char *version)
{
    int result = MAVIS_INIT_OK;

    DebugIn(DEBUG_MAVIS);

    mavis_check_version(version);

    if (!mcx) {
	Debug((DEBUG_MAVIS, "- %s: FATAL: no modules configured\n", __func__));
	logmsg("Fatal: No modules configured");
	exit(EX_USAGE);
    }

    result = mcx->init(mcx);
    Debug((DEBUG_MAVIS, "- %s = %d\n", __func__, result));
    return result;
}

int mavis_drop(mavis_ctx * mcx)
{
    void *handle = NULL;

    DebugIn(DEBUG_MAVIS);

    if (mcx)
	handle = mcx->drop(mcx);
    if (handle)
	dlclose(handle);

    DebugOut(DEBUG_MAVIS);
    return 0;
}

int mavis_parse(mavis_ctx * mcx, struct sym *sym, char *id)
{
    int result = MAVIS_CONF_ERR;

    DebugIn(DEBUG_MAVIS);

    if (mcx)
	result = mcx->parse(mcx, sym, id);
    DebugOut(DEBUG_MAVIS);
    return result;
}

static int mavis_sanitycheck(mavis_ctx * mcx, av_ctx * ac)
{
    if (!mcx) {
	av_set(ac, AV_A_RESULT, AV_V_RESULT_ERROR);
	av_set(ac, AV_A_COMMENT, "no modules installed");
	return -1;
    }
    if (ac->arr[AV_A_TYPE] && ((!strcmp(ac->arr[AV_A_TYPE], AV_V_TYPE_FTP) && ac->arr[AV_A_USER]
				&& ac->arr[AV_A_PASSWORD] && ac->arr[AV_A_IPADDR])
			       || (!strcmp(ac->arr[AV_A_TYPE], AV_V_TYPE_TACPLUS)
				   && ac->arr[AV_A_USER] && ac->arr[AV_A_TACTYPE])
			       || !strcmp(ac->arr[AV_A_TYPE], AV_V_TYPE_LOGSTATS)))
	return 0;
    av_set(ac, AV_A_RESULT, AV_V_RESULT_ERROR);
    av_set(ac, AV_A_COMMENT, "invalid request");
    return -1;
}

char *av_addserial(av_ctx * ac)
{
    if (!ac->arr[AV_A_SERIAL]) {
	u_char u[16];
	char b[30];
	size_t i, len = (int) sizeof(b);
	myMD5_CTX m;
	myMD5Init(&m);
	for (i = 0; i < AV_A_ARRAYSIZE; i++)
	    if (ac->arr[i])
		myMD5Update(&m, (u_char *) ac->arr[i], strlen(ac->arr[i]));
	myMD5Final(u, &m);
	base64enc((char *) u, (size_t) 16, b, &len);
	av_set(ac, AV_A_SERIAL, b);
    }
    return ac->arr[AV_A_SERIAL];
}

int mavis_send(mavis_ctx * mcx, av_ctx ** ac)
{
    int result = MAVIS_IGNORE;

    DebugIn(DEBUG_MAVIS);

    if (mcx) {
	if (!mavis_sanitycheck(mcx, *ac)) {
	    av_addserial(*ac);
	    if (!strcmp((*ac)->arr[AV_A_TYPE], AV_V_TYPE_LOGSTATS))
		av_set(*ac, AV_A_RESULT, AV_V_RESULT_OK);

	    result = mcx->send(mcx, ac);

	    if (result == MAVIS_FINAL && !(*ac)->arr[AV_A_RESULT])
		av_set(*ac, AV_A_RESULT, AV_V_RESULT_NOTFOUND);
	}
    }
    Debug((DEBUG_MAVIS, "- %s (%d)\n", __func__, result));
    return result;
}

int mavis_cancel(mavis_ctx * mcx, void *app_ctx)
{
    int result = MAVIS_IGNORE;

    DebugIn(DEBUG_MAVIS);

    result = mcx->cancel(mcx, app_ctx);

    Debug((DEBUG_MAVIS, "- %s (%d)\n", __func__, result));
    return result;
}

int mavis_recv(mavis_ctx * mcx, av_ctx ** ac, void *app_ctx)
{
    int result;
    DebugIn(DEBUG_MAVIS);
    result = mcx->recv(mcx, ac, app_ctx);
    if (result == MAVIS_FINAL_DEFERRED)
	result = MAVIS_FINAL;
    DebugOut(DEBUG_MAVIS);
    return result;
}

void av_clear(av_ctx * ac)
{
    DebugIn(DEBUG_AV);
    if (ac) {
	int i;

	for (i = 0; i < AV_A_ARRAYSIZE; i++)
	    Xfree(&ac->arr[i]);
    }
    DebugOut(DEBUG_AV);
}

void av_move(av_ctx * ac_out, av_ctx * ac_in)
{
    int i;

    DebugIn(DEBUG_AV);
    av_clear(ac_out);

    for (i = 0; i < AV_A_ARRAYSIZE; i++) {
	ac_out->arr[i] = ac_in->arr[i];
	ac_in->arr[i] = NULL;
    }

    DebugOut(DEBUG_AV);
}

void av_copy(av_ctx * ac_out, av_ctx * ac_in)
{
    int i;

    DebugIn(DEBUG_AV);
    av_clear(ac_out);

    for (i = 0; i < AV_A_ARRAYSIZE; i++) {
	Xfree(&ac_out->arr[i]);
	if (ac_in->arr[i])
	    ac_out->arr[i] = strdup(ac_in->arr[i]);
    }

    DebugOut(DEBUG_AV);
}

void av_merge(av_ctx * ac_out, av_ctx * ac_in)
{
    int i;

    DebugIn(DEBUG_AV);

    for (i = 0; i < AV_A_ARRAYSIZE; i++)
	if (!ac_out->arr[i] && ac_in->arr[i])
	    ac_out->arr[i] = strdup(ac_in->arr[i]);

    DebugOut(DEBUG_AV);
}

void av_set(av_ctx * ac, int av_attribute, char *av_value)
{
    if (av_attribute < 0 || av_attribute >= AV_A_ARRAYSIZE) {
	Debug((DEBUG_AV, "%s(%d) out of bounds\n", __func__, av_attribute));
	return;
    }

    Debug((DEBUG_AV, " %s(%s) = %-20s\n", __func__, av_char[av_attribute].name, av_value ? av_value : "(NULL)"));

    Xfree(&ac->arr[av_attribute]);

    if (av_value)
	ac->arr[av_attribute] = Xstrdup(av_value);
    else
	ac->arr[av_attribute] = NULL;
}

void av_setf(av_ctx * ac, int av_attribute, char *format, ...)
{
    size_t len = 1024, nlen;
    va_list ap;
    char *tmpbuf = alloca(len);

    va_start(ap, format);
    nlen = vsnprintf(tmpbuf, len, format, ap);
    va_end(ap);
    if (len <= nlen) {
	tmpbuf = alloca(++nlen);
	va_start(ap, format);
	vsnprintf(tmpbuf, nlen, format, ap);
	va_end(ap);
    }
    va_end(ap);
    av_set(ac, av_attribute, tmpbuf);
}

char *av_get(av_ctx * ac, int av_attribute)
{
    if (av_attribute < 0 || av_attribute > AV_A_ARRAYSIZE) {
	Debug((DEBUG_AV, "%s(%d): out of bounds\n", __func__, av_attribute));
	return NULL;
    }
#ifdef DEBUG
    if (ac->arr[av_attribute])
	Debug((DEBUG_AV, " %s(%s) = %-20s\n", __func__, av_char[av_attribute].name, ac->arr[av_attribute] ? ac->arr[av_attribute] : "(NULL)"));
#endif

    return ac->arr[av_attribute];
}

void av_dump(av_ctx * ac)
{
    int i;

    fprintf(stderr, "attribute-value-pairs:\n");
    for (i = 0; i < AV_A_ARRAYSIZE; i++)
	if (ac->arr[i])
	    fprintf(stderr, "%-20s%s\n", av_char[i].name, ac->arr[i]);
    fprintf(stderr, "\n");
}

int av_attribute_to_i(char *s)
{
    int i;

    for (i = 0; i < AV_A_ARRAYSIZE; i++)
	if (!strcasecmp(av_char[i].name, s) || (av_char[i].token && !strcmp(codestring[av_char[i].token], s)))
	    return i;
    return -1;
}

int av_attr_token_to_i(struct sym *sym)
{
    char *b = sym->buf;
    if (sym->code) {
	int i;
	for (i = 0; i < AV_A_ARRAYSIZE; i++)
	    if (av_char[i].token && (av_char[i].token == sym->code))
		return i;
    }
    if (*b == '$')
	b++;
    return av_attribute_to_i(b);
}

int av_array_to_char(av_ctx * ac, char *buffer, size_t buflen, fd_set * set)
{
    int i, j, k;
    char *u;
    char *t = buffer;

    buffer[0] = 0;

    for (i = 0; i < AV_A_ARRAYSIZE; i++)
	if ((!set || FD_ISSET(i, set)) && (u = av_get(ac, i))) {
	    j = snprintf(t, (size_t) (buffer + buflen - t), "%d %s\n", i, u);
	    if (j >= buffer + buflen - t)
		return -1;
	    for (k = 0; k < j - 1; k++)
		if (t[k] == '\n')
		    t[k] = '\r';
	    t += j;
	}

    return (int) (t - buffer);
}

int av_char_to_array(av_ctx * ac, char *buffer, fd_set * set)
{
    char *av_start = buffer;
    char *av_end = av_start;
    int av_attribute;
    char *av_value;

    while ((av_end = strchr(av_end, '\n'))) {
	*av_end = 0;
	av_value = strchr(av_start, ' ');
	if (av_value) {
	    *av_value++ = 0;
	    if ((1 == sscanf(av_start, "%d", &av_attribute)) && (!set || FD_ISSET(av_attribute, set))) {
		char *t;
		av_set(ac, av_attribute, av_value);
		t = av_get(ac, av_attribute);
		if (t)
		    while (*t) {
			if (*t == '\r')
			    *t = '\n';
			t++;
		    }
	    }
	    *(av_value - 1) = ' ';
	}
	*av_end++ = '\n';
	av_start = av_end;
    }

    return 0;
}

av_ctx *av_new(void *cb, void *ctx)
{
    av_ctx *a = Xcalloc((size_t) 1, sizeof(av_ctx));
    a->app_cb = cb;
    a->app_ctx = ctx;
    return a;
}

void av_setcb(av_ctx * a, void *cb, void *ctx)
{
    a->app_cb = cb;
    a->app_ctx = ctx;
}

void av_free(av_ctx * ac)
{
    if (ac) {
	int i;
	for (i = 0; i < AV_A_ARRAYSIZE; i++)
	    Xfree(&ac->arr[i]);
	free(ac);
    }
}

void av_free_private(av_ctx * ac)
{
    if (ac) {
	int i;
	for (i = 0; i < AV_A_ARRAYSIZE; i++)
	    switch (i) {
	    case AV_A_PATH:
	    case AV_A_UID:
	    case AV_A_GID:
	    case AV_A_HOME:
	    case AV_A_ROOT:
	    case AV_A_SHELL:
	    case AV_A_GIDS:
	    case AV_A_MEMBEROF:
	    case AV_A_DN:
	    case AV_A_IDENTITY_SOURCE:
	    case AV_A_SSHKEYHASH:
	    case AV_A_SSHKEY:
	    case AV_A_SSHKEYID:
	    case AV_A_ARGS:
	    case AV_A_RARGS:
	    case AV_A_VERDICT:
		break;
	    default:
		Xfree(&ac->arr[i]);
	    }
    }
}

int mavis_check_version(char *version)
{
    if (strcmp(version, MAVIS_API_VERSION)) {
	logmsg("Warning: MAVIS library API version mismatch (%s vs. %s). Expect trouble.", version, MAVIS_API_VERSION);
	return -1;
    }
    return 0;
}

void mavis_detach(void)
{
    int devnull;

    setsid();
    devnull = open("/dev/null", O_RDWR);
    dup2(devnull, 1);
    close(devnull);
    fcntl(0, F_SETFD, fcntl(0, F_GETFD, 0) | FD_CLOEXEC);
    fcntl(1, F_SETFD, fcntl(1, F_GETFD, 0) | FD_CLOEXEC);
}

char *escape_string(char *in, size_t inlen, char *out, size_t *outlen)
{
    char *v = out, *t;
    size_t outlen_max = *outlen - 4, len = 0;
    for (t = in; inlen && len < outlen_max; t++, inlen--) {
	int c = *t;
	if (iscntrl(c)) {
	    *v++ = '\\';
	    switch (c) {
	    case '\a':
		*v++ = 'a';
		break;
	    case '\b':
		*v++ = 'b';
		break;
	    case '\v':
		*v++ = 'v';
		break;
	    case '\f':
		*v++ = 'f';
		break;
	    case '\n':
		*v++ = 'n';
		break;
	    case '\r':
		*v++ = 'r';
		break;
	    case '\t':
		*v++ = 't';
		break;
	    default:
		*v++ = '0' + ((c >> 6) & 7);
		*v++ = '0' + ((c >> 3) & 7);
		*v++ = '0' + (c & 7);
		len++;
		len++;
	    }
	    len++;
	} else {
	    if (*t == '\\') {
		*v++ = *t;
		len++;
	    }
	    *v++ = *t;
	}
	len++;
    }

    *v = 0;
    *outlen = len;
    return out;
}

/*
 * log.c
 * (C)1998-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include "headers.h"
#include "misc/version.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

static char *subst_delim(char *text, int sub)
{
    if (sub) {
	static char b[4 * PATH_MAX];
	char *t;

	strncpy(b, text, sizeof(b));
	b[sizeof(b) - 1] = 0;

	for (t = b; *t; t++)
	    if (*t == logformat_delimiter)
		*t = logformat_substitute;
	return b;
    }
    return text;
}

/* magic cookie substitution */
char *cook(struct context *ctx, char *format, char *direction, char *command, int sub)
{
    char buf[INET6_ADDRSTRLEN];
    static char b[2 * PATH_MAX], *tmax = b + sizeof(b) - 1;
    char *t = b;

    b[0] = 0;

    while (*format && t < tmax) {
	if (*format == '%')
	    switch (*++format) {
	    case 'A':
		t += snprintf(t, (size_t) (tmax - t), "%d", ctx->count_total);
		break;
	    case 'B':
		t += snprintf(t, (size_t) (tmax - t), "%s", subst_delim(__DATE__ " " __TIME__, sub));
		break;
	    case 'C':
		t += snprintf(t, (size_t) (tmax - t), "%s", (ctx->cwdlen == ctx->rootlen)
			      ? "/" : ctx->cwd + ctx->rootlen);
		break;
	    case 'D':
		t += snprintf(t, (size_t) (tmax - t), "%lu", (u_long) (io_now.tv_sec - ctx->transferstart));
		break;
	    case 'E':
		if (ctx->maintainer)
		    t += snprintf(t, (size_t) (tmax - t), "%s", subst_delim(ctx->maintainer, sub));
		break;
	    case 'F':
		t += snprintf(t, (size_t) (tmax - t), "%d", ctx->count_files);
		break;
	    case 'H':
		if (ctx->vhost) {
		    t += snprintf(t, (size_t) (tmax - t), "%s", subst_delim(ctx->vhost, sub));
		    break;
		}
	    case 'L':
		if (ctx->hostname)
		    t += snprintf(t, (size_t) (tmax - t), "%s", subst_delim(ctx->hostname, sub));
		break;
	    case 'I':
		t += snprintf(t, (size_t) (tmax - t), "%s", ctx->anonymous ? (ctx->email ? ctx->email : "")
			      : (ctx->user ? ctx->user : ""));
		break;
	    case 'P':
		if (ctx->anonymous && ctx->email)
		    t += snprintf(t, (size_t) (tmax - t), "%s", subst_delim(ctx->email, sub));
		break;
	    case 'R':
#ifdef WITH_DNS
		if (ctx->reverse)
		    t += snprintf(t, (size_t) (tmax - t), "%s", subst_delim(ctx->reverse, sub));
		else
#endif				/* WITH_DNS */
		    t += snprintf(t, (size_t) (tmax - t), "[%s]", subst_delim(su_ntop(&ctx->sa_c_remote, buf, (socklen_t) sizeof(buf)), sub));
		break;
	    case 'T':
		{
		    time_t tt = (time_t) (io_now.tv_sec);
		    t += strftime(t, (size_t) (tmax - t), "%a %b %d %T %Z %Y", localtime(&tt));
		}
		break;
	    case 'U':
		if (ctx->user)
		    t += snprintf(t, (size_t) (tmax - t), "%s", subst_delim(ctx->user, sub));
		break;
	    case 'V':
		t += snprintf(t, (size_t) (tmax - t), "%s", subst_delim(VERSION, sub));
		break;
	    case 'a':
		t += snprintf(t, (size_t) (tmax - t), "%llu", (unsigned long long) ctx->traffic_total);
		break;
	    case 'b':
		t += snprintf(t, (size_t) (tmax - t), "%llu", (unsigned long long) ctx->bytecount);
		break;
	    case 'c':
		if (command)
		    t += snprintf(t, (size_t) (tmax - t), "%s", subst_delim(command, sub));
		break;
	    case 'd':
	    case 'e':
		if (direction)
		    t += snprintf(t, (size_t) (tmax - t), "%s", direction);
		break;
	    case 'f':
		t += snprintf(t, (size_t) (tmax - t), "%lld", ctx->traffic_files);
		break;
	    case 'i':
		t += snprintf(t, (size_t) (tmax - t), "%.8lx", ctx->id);
		break;
	    case 'l':
		t += snprintf(t, (size_t) (tmax - t), "%s", subst_delim(su_ntop(&ctx->sa_c_local, buf, (socklen_t) sizeof(buf)), sub));
		break;
	    case 'm':
		if (t < tmax) {
		    if (ctx->use_ascii)
			*t++ = 'a';
		    else
			*t++ = 'b';
		}
		break;
	    case 'r':
		t += snprintf(t, (size_t) (tmax - t), "%s", subst_delim((char *) su_ntop(&ctx->sa_c_remote, buf, (socklen_t) sizeof(buf)), sub));
		break;
	    case 's':
		t += snprintf(t, (size_t) (tmax - t), "%llu", (unsigned long long) ctx->filesize);
		break;
	    case 't':
		if (t < tmax) {
		    if (ctx->real)
			*t++ = 'r';
		    else if (ctx->anonymous)
			*t++ = 'a';
		    else
			*t++ = 'u';
		}
		break;
	    case 'u':
		if (ctx->ident_user)
		    t += snprintf(t, (size_t) (tmax - t), "%s", subst_delim(ctx->ident_user, sub));
		break;
	    case '%':
		if (t < tmax)
		    *t++ = '%';
		break;
	} else if (t < tmax)
	    *t++ = *format;
	if (*format)
	    format++;
    }
    *t = 0;
    return b;
}

void ftp_log(struct context *ctx, u_int loglevel, char *arg)
{
    if ((!(loglevel & LOG_OVERRIDE) && !(ctx->loglevel & loglevel))
	|| !arg)
	return;

    loglevel &= ~LOG_OVERRIDE;

    if (loglevel == LOG_TRANSFER && (!ctx->filename[0] || ctx->conversion))
	return;

    switch (loglevel) {
    case LOG_TRANSFER:
	logmsg("%s", cook(ctx, logformat_transfer, arg, ctx->filename, 1));
	break;
    case LOG_COMMAND:
	logmsg("%s", cook(ctx, logformat_command, ":", arg, 1));
	break;
    case LOG_EVENT:
	logmsg("%s", cook(ctx, logformat_event, arg, "", 1));
	break;
    }
    ctx->bytecount = 0;
}

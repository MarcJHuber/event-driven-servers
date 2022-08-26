/*
 * reply.c
 * (C)1998-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include "headers.h"
#include <stdarg.h>
#include <arpa/telnet.h>

static const char rcsid[] __attribute__((used)) = "$Id$";

/*
 * For data written to the command channel we need to follow
 * Telnet NVT conventions.
 */

struct buffer *buffer_reply(struct buffer *b, char *s, size_t len)
{
    size_t j = 2 * len;
    char *a = alloca(j);
    char *t = a, *se = s + len;
    DebugIn(DEBUG_PROC);

    for (; s < se; s++) {
	*t++ = *s;
	if (*s == '\r')
	    /* <CR> => <CR><NUL> */
	    *t++ = 0, len++;
	else if ((u_char) * s == IAC)
	    *t++ = 0xff /* IAC */ , len++;
    }
    b = buffer_write(b, a, len);
    DebugOut(DEBUG_PROC);
    return b;
}

void replyf(struct context *ctx, char *format, ...)
{
    ssize_t len = 1024, nlen;
    size_t j = 2 * len;
    char *tmpbuf;

    DebugIn(DEBUG_PROC);

  again:
    tmpbuf = alloca(j);

    if (ctx && ctx->cfn > -1) {
	va_list ap;
	va_start(ap, format);
	nlen = vsnprintf(tmpbuf, len, format, ap);
	va_end(ap);
	if (len <= nlen) {
	    j = 2 * ++nlen;
	    goto again;
	}
	len = nlen;

	if (len > -1) {
	    char *t = tmpbuf + len - 1;
	    char *u = tmpbuf + 2 * len - 1;
	    ssize_t f;

	    /* <CR><NL> at the end of the format string is ok */
	    if (len > 1 && ((f = strlen(format)) > 1)
		&& format[f - 2] == '\r' && format[f - 1] == '\n') {
		*u-- = *t--;
		*u-- = *t--;
	    }

	    for (; t >= tmpbuf; *u-- = *t--)
		if (*t == '\r')
		    /* <CR> => <CR><NUL> */
		    *u-- = 0, len++;
		else if ((u_char) * t == IAC)
		    /* <IAC> => <IAC><IAC> */
		    *u-- = 0xff /* IAC */ , len++;
	    ctx->cbufo = buffer_write(ctx->cbufo, u + 1, len);

	    io_set_o(ctx->io, ctx->cfn);
	}
    }
    DebugOut(DEBUG_PROC);
}

void reply(struct context *ctx, char *s)
{
    DebugIn(DEBUG_PROC);

    if (ctx && ctx->cfn > -1) {
	size_t len = strlen(s);
	if (len > 1 && s[len - 2] == '\r' && s[len - 1] == '\n') {
	    /* Don't escape <CR><LF> at end of string */
	    ctx->cbufo = buffer_reply(ctx->cbufo, s, len - 2);
	    ctx->cbufo = buffer_write(ctx->cbufo, "\r\n", 2);
	} else
	    ctx->cbufo = buffer_reply(ctx->cbufo, s, len);

	io_set_o(ctx->io, ctx->cfn);
    }
    DebugOut(DEBUG_PROC);
}

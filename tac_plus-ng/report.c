/*
   Copyright (C) 1999-2022 Marc Huber (Marc.Huber@web.de)
   All rights reserved.

   Redistribution and use in source and binary  forms,  with or without
   modification, are permitted provided  that  the following conditions
   are met:

   1. Redistributions of source code  must  retain  the above copyright
      notice, this list of conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions  and  the following disclaimer in
      the  documentation  and/or  other  materials  provided  with  the
      distribution.

   3. The end-user documentation  included with the redistribution,  if
      any, must include the following acknowledgment:

          This product includes software developed by Marc Huber
	  (Marc.Huber@web.de).

      Alternately,  this  acknowledgment  may  appear  in  the software
      itself, if and wherever such third-party acknowledgments normally
      appear.

   THIS SOFTWARE IS  PROVIDED  ``AS IS''  AND  ANY EXPRESSED OR IMPLIED
   WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
   MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
   IN NO EVENT SHALL  ITS  AUTHOR  BE  LIABLE FOR ANY DIRECT, INDIRECT,
   INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
   BUT NOT LIMITED  TO,  PROCUREMENT OF  SUBSTITUTE  GOODS OR SERVICES;
   LOSS OF USE,  DATA,  OR PROFITS;  OR  BUSINESS INTERRUPTION) HOWEVER
   CAUSED AND ON ANY THEORY OF LIABILITY,  WHETHER IN CONTRACT,  STRICT
   LIABILITY,  OR TORT  (INCLUDING NEGLIGENCE OR OTHERWISE)  ARISING IN
   ANY WAY OUT OF THE  USE  OF  THIS  SOFTWARE,  EVEN IF ADVISED OF THE
   POSSIBILITY OF SUCH DAMAGE.
 */

#include "headers.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

static __inline__ int report_flag_set(tac_session * session, int priority, int level)
{
    int res = (common_data.debug & level) || (session && (session->debug & level));	// debug mode
    res &= common_data.debugtty || common_data.debug_redirected || common_data.syslog_dflt;	//  and output to tty, file or syslog
    res |= common_data.syslog_dflt && (priority != LOG_DEBUG);	// or not in debug mode
    return res;
}

void report(tac_session * session, int priority, int level, char *fmt, ...)
{
    int len = 2048;
    char *nas_addr = "-";
    char *msg = alloca(len);
    va_list ap;
    int nlen;
    if (!report_flag_set(session, priority, level))
	return;

    va_start(ap, fmt);
    nlen = vsnprintf(msg, len, fmt, ap);
    va_end(ap);
    if (len <= nlen) {
	msg = alloca(++nlen);
	va_start(ap, fmt);
	vsnprintf(msg, nlen, fmt, ap);
	va_end(ap);
    }

    if (session && session->ctx && session->ctx->nas_address_ascii)
	nas_addr = session->ctx->nas_address_ascii;

    if ((common_data.debug & level) || (session && (session->debug & level))) {
	if (common_data.debug & DEBUG_TACTRACE_FLAG) {
	    fprintf(stderr, "%s %s\n", nas_addr, msg);
	    fflush(stderr);
	    return;
	}
	if (common_data.debugtty || common_data.debug_redirected) {
	    static pid_t pid = 0;
	    if (!pid)
		pid = getpid();
	    static char now[80];
	    static struct timeval last = { 0 };
	    if (!io_now.tv_sec)
		io_now.tv_sec = time(NULL);
	    if (last.tv_sec != io_now.tv_sec || last.tv_usec != io_now.tv_usec) {
		last.tv_sec = io_now.tv_sec;
		last.tv_usec = io_now.tv_usec;
		*now = 0;
		time_t dummy = (time_t) io_now.tv_sec;
		if (!dummy)
		    dummy = time(NULL);
		struct tm *tm = localtime(&dummy);
		strftime(now, sizeof(now), "%H:%M:%S", tm);
	    }
	    fprintf(stderr, "%ld: %s.%.3lu %x/%.8x: %s %s\n", (long int) pid,
		    now, (u_long) io_now.tv_usec / 1000, (session
							  && session->ctx) ? session->ctx->id : 0, session ? ntohl(session->session_id) : 0, nas_addr, msg);
	    fflush(stderr);
	    return;
	}
	if (common_data.syslog_dflt) {
	    syslog(LOG_DEBUG, "%x/%.8x: %s %s%s",
		   (session && session->ctx) ? session->ctx->id : 0,
		   session ? ntohl(session->session_id) : 0, nas_addr, (priority & LOG_PRIMASK) == LOG_ERR ? "Error: " : "", msg);
	    return;
	}
    }

    if (priority != LOG_DEBUG && common_data.syslog_dflt)
	syslog(priority, "%s %s%s", nas_addr, (priority & LOG_PRIMASK) == LOG_ERR ? "Error: " : "", msg);
}

void report_hex(tac_session * session, int priority, int level, u_char * ptr, int len)
{
    u_char *p = ptr;
    while (len > 0) {
	char hex[] = "0123456789abcdef", buf[80];
	char *b = buf + 5, *t = buf + 55;
	int i, l = len < 16 ? len : 16;

	memset(b, ' ', sizeof(buf) - 5);
	snprintf(buf, sizeof(buf), "%.4x ", (int) (p - ptr));

	for (i = 0; i < l; i++, b++, p++) {
	    if (i == 8)
		b++, t++;
	    *b++ = hex[(*p >> 4) & 0xf];
	    *b++ = hex[*p & 0xf];
	    *t++ = isprint((int) *p) ? (char) *p : '.';
	}
	*t = 0;
	len -= i;

	report(session, priority, level, "%s%s%s", common_data.font_red, buf, common_data.font_plain);
    }
}

void report_string(tac_session * session, int priority, int level, char *pre, char *p, int len)
{
    if (report_flag_set(session, priority, level)) {
	size_t outlen = len * 4 + 1;
	char *v = alloca(outlen);
	char *m = escape_string(p, len, v, &outlen);

	report(session, priority, level, "%s%s%s (len: %d): %s%s%s", common_data.font_red, pre, common_data.font_plain, len, common_data.font_blue, m,
	       common_data.font_plain);
	if (level & DEBUG_HEX_FLAG)
	    report_hex(session, priority, level, (u_char *) p, len);
    }
}

/*
   Copyright (C) 1999-2016 Marc Huber (Marc.Huber@web.de)
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

/*
   Copyright (c) 1995-1998 by Cisco systems, Inc.

   Permission to use, copy, modify, and distribute this software for
   any purpose and without fee is hereby granted, provided that this
   copyright and permission notice appear on all copies of the
   software and supporting documentation, the name of Cisco Systems,
   Inc. not be used in advertising or publicity pertaining to
   distribution of the program without specific prior permission, and
   notice be given in supporting documentation that modification,
   copying and distribution is by permission of Cisco Systems, Inc.

   Cisco Systems, Inc. makes no representations about the suitability
   of this software for any purpose.  THIS SOFTWARE IS PROVIDED ``AS
   IS'' AND WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING,
   WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
   FITNESS FOR A PARTICULAR PURPOSE.
*/


#include <stdio.h>
#include <setjmp.h>
#include <syslog.h>
#include <sysexits.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <pwd.h>
#include <grp.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <glob.h>
#ifndef GLOB_NOMAGIC
#define GLOB_NOMAGIC 0
#endif
#ifndef GLOB_BRACE
#define GLOB_BRACE 0
#endif
#ifndef GLOB_NOESCAPE
#define GLOB_NOESCAPE 0
#endif

#ifdef WITH_PCRE
#include <pcre.h>
#endif
#ifdef WITH_PCRE2
#include <pcre2.h>
#endif

#include <regex.h>

#include "log.h"
#include "misc/ostype.h"
#include "mavis.h"
#include "spawnd_headers.h"
#include "misc/strops.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

struct common_data common_data;

void init_common_data(void)
{
    memset(&common_data, 0, sizeof common_data);
    common_data.syslog_facility = LOG_UUCP;
    common_data.syslog_level = LOG_INFO;
    common_data.syslog_dflt = 1;
    if ((common_data.debugtty = isatty(2))) {
	common_data.font_black = "\033[1;30m";
	common_data.font_red = "\033[1;31m";
	common_data.font_green = "\033[1;32m";
	common_data.font_yellow = "\033[1;33m";
	common_data.font_blue = "\033[1;34m";
	common_data.font_magenta = "\033[1;35m";
	common_data.font_cyan = "\033[1;36m";
	common_data.font_white = "\033[1;37m";
	common_data.font_plain = "\033[1;0m";
	common_data.font_bold = "\033[1;1m";
    } else {
	common_data.font_black = "";
	common_data.font_red = "";
	common_data.font_green = "";
	common_data.font_yellow = "";
	common_data.font_blue = "";
	common_data.font_magenta = "";
	common_data.font_cyan = "";
	common_data.font_white = "";
	common_data.font_plain = "";
	common_data.font_bold = "";
    }
    common_data.pid = getpid();

    {
	char *g[] = { "/usr/bin/gcore", "/usr/local/bin/gcore", NULL };
	char **gc = g;
	while (*gc && access(*gc, X_OK))
	    gc++;
	common_data.gcorepath = *gc;
    }

    common_data.scm_send_msg = scm_send_msg;
    common_data.scm_recv_msg = scm_recv_msg;
#ifdef WITH_PCRE
    common_data.regex_pcre_flags = PCRE_CASELESS;
#endif
#ifdef WITH_PCRE2
    common_data.regex_pcre_flags = PCRE2_CASELESS | PCRE2_UTF;
#endif
    common_data.regex_posix_flags = REG_ICASE;
    logopen();
}

void parse_error(struct sym *sym, char *fmt, ...)
{
    char msg[2 * MAX_INPUT_LINE_LEN];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    if (common_data.debugtty)
	fprintf(stderr, "%.*s\n%s:%u: %s\n", sym->len - sym->tlen, sym->in, sym->filename, sym->line, msg);
    report_cfg_error(LOG_ERR, ~0, "%s:%u: %s", sym->filename, sym->line, msg);

    while (sym->next)
	sym = sym->next;
    if (sym->env_valid)
	longjmp(sym->env, 1);
    exit(EX_CONFIG);
}

void parse_error_expect(struct sym *sym, enum token token, ...)
{
    char s[1024];
    int len = (int) sizeof(s) - 1;
    char *p = s;
    va_list ap;
    *s = 0;

    va_start(ap, token);

    do {
	enum token next_token = (enum token) va_arg(ap, int);
	if (s != p) {
	    if (next_token == S_unknown)
		strncpy(p, " or '", len);
	    else
		strncpy(p, ", '", len);
	} else
	    strncpy(p, " '", len);
	while (*p)
	    p++, len--;
	strncpy(p, codestring[token], len);
	while (*p)
	    p++, len--;
	strncpy(p, "'", len);
	while (*p)
	    p++, len--;
	token = next_token;
    }
    while (token != S_unknown);

    va_end(ap);

    parse_error(sym, "Expected%s, but got '%s'", s, sym->buf);

}

enum token parse_permission(struct sym *sym)
{
    enum token sc = sym->code;

    switch (sc) {
    default:
	parse_error_expect(sym, S_permit, S_deny, S_unknown);
    case S_permit:
    case S_deny:
	sym_get(sym);
	return sc;
    }
}

u_int parse_bool(struct sym *sym)
{
    enum token sc = sym->code;

    switch (sc) {
    default:
	parse_error_expect(sym, S_yes, S_no, S_permit, S_deny, S_unknown);
    case S_yes:
    case S_permit:
	sym_get(sym);
	return 1;
    case S_no:
    case S_deny:
	sym_get(sym);
	return 0;
    }
}

int parse_comma(struct sym *sym)
{
    int res = 0;
    while (sym->code == S_comma) {
	sym_get(sym);
	res = -1;
    }
    return res;
}

void parse(struct sym *sym, enum token sc)
{
    if (sym->code != sc)
	parse_error_expect(sym, sc, S_unknown);
    sym_get(sym);
}

static void sym_getchar(struct sym *sym)
{
    if (sym->tlen < 1) {
	*(sym->ch) = CHAREOF;
	sym->chlen = 1;
    } else {
	int i;
	sym->chlen = 1;
	sym->start = sym->tin;
	if (sym->tlen > 1 && ((*sym->tin & 0xE0) == 0xC0) && (*(sym->tin + 1) & 0xC0) == 0x80)
	    sym->chlen = 2;
	else if (sym->tlen > 2 && (*sym->tin & 0xF0) == 0xE0 && (*(sym->tin + 1) & 0xC0) == 0x80 && (*(sym->tin + 2) & 0xC0) == 0x80)
	    sym->chlen = 3;
	else if (sym->tlen > 3 && (*sym->tin & 0xF8) == 0xF0 && (*(sym->tin + 1) & 0xC0) == 0x80
		 && (*(sym->tin + 2) & 0xC0) == 0x80 && (*(sym->tin + 3) & 0xC0) == 0x80)
	    sym->chlen = 4;
	for (i = 0; i < sym->chlen; i++) {
	    sym->ch[i] = *sym->tin;
	    sym->tin++;
	    sym->tlen--;
	}
    }
}

static void sym_start(struct sym *sym)
{
    sym->pos = 0;
    sym->raw = sym->start;
}

static void substitute_envvar(struct sym *sym)
{
    int found = 0;
    char *t = sym->buf;
    char buf[MAX_INPUT_LINE_LEN];
    char *b = buf;
    char *be = buf + MAX_INPUT_LINE_LEN - 1;
    while (*t) {
	if (*t == '$' && *(t + 1) == '{') {
	    char *var;
	    u_int var_len;
	    char *vs = t + 2;
	    char *ve = vs;
	    while (*ve && *ve != '}')
		ve++;
	    if (ve) {
		var_len = ve - vs + 1;
		var = alloca(var_len);
		if (var) {
		    memcpy(var, vs, var_len);
		    var[var_len - 1] = 0;
		    var = getenv(var);
		    found = 1;
		    if (var) {
			t = ve;
			t++;
			while (b < be && *var)
			    *b++ = *var++;
			continue;
		    }
		}
	    }
	}
	if (b < be)
	    *b++ = *t;
	t++;
    }
    *b++ = 0;
    if (found) {
	report_cfg_error(LOG_DEBUG, DEBUG_PARSE_FLAG,
			 "file=%s line=%u sym=[%s%s%s] buf='%s%s%s' => buf='%s%s%s'",
			 sym->filename ? sym->filename : "(unset)",
			 sym->line, common_data.font_red,
			 codestring[sym->code], common_data.font_plain, common_data.font_blue, sym->buf, common_data.font_plain, common_data.font_blue, buf,
			 common_data.font_plain);
	memcpy(sym->buf, buf, b - buf);
    }
}

void getsym(struct sym *sym)
{
    *sym->buf = 0;
    sym->quoted = 0;
    sym->raw = sym->start;
    while (1)
	switch (*sym->ch) {
	case 0:
	case CHAREOF:
	    sym->code = S_eof;
	    return;
	case '\n':
	    sym->line++;
	case '\r':
	case '\t':
	case ' ':
	    sym_getchar(sym);
	    continue;
	case '=':
	    sym->code = S_equal;
	  sym_code_to_buf:
	    sym->buf[0] = *sym->ch;
	    sym->buf[1] = 0;
	    sym_getchar(sym);
	    return;
	case ',':
	    sym->code = S_comma;
	    goto sym_code_to_buf;
	case '{':
	    sym->code = S_openbra;
	    goto sym_code_to_buf;
	case '}':
	    sym->code = S_closebra;
	    goto sym_code_to_buf;
	case '!':
	    sym->code = S_exclmark;
	    goto sym_code_to_buf;
	case '(':
	    sym->code = S_leftbra;
	    goto sym_code_to_buf;
	case ')':
	    sym->code = S_rightbra;
	    goto sym_code_to_buf;
	case '[':
	    sym->code = S_leftsquarebra;
	    goto sym_code_to_buf;
	case ']':
	    sym->code = S_rightsquarebra;
	    goto sym_code_to_buf;
	case '&':
	    sym_start(sym);
	    buf_add(sym, *sym->ch);
	    sym->code = S_string;
	    buf_add(sym, *sym->ch);
	    sym_getchar(sym);
	    if (*sym->ch == '&') {
		buf_add(sym, *sym->ch);
		buf_add(sym, 0);
		sym_getchar(sym);
		sym->code = S_and;
		return;
	    }
	    continue;
	case '|':
	    sym_start(sym);
	    buf_add(sym, *sym->ch);
	    sym->code = S_string;
	    buf_add(sym, *sym->ch);
	    sym_getchar(sym);
	    if (*sym->ch == '|') {
		buf_add(sym, *sym->ch);
		buf_add(sym, 0);
		sym_getchar(sym);
		sym->code = S_or;
		return;
	    }
	    continue;
	case '#':
	    while (*sym->ch != '\n' && *sym->ch != '\r' && *sym->ch != (char) EOF)
		sym_getchar(sym);
	    continue;
	case '"':
	    sym_start(sym);
	    sym_getchar(sym);
	    /* implement C style quoting */
	    while (*sym->ch != '"') {
		int i;
		if (*sym->ch == (char) EOF)
		    parse_error(sym, "EOF unexpected");
		if (*sym->ch == '\n')
		    sym->line++;
		if (*sym->ch == '\\') {
		    char scc, sc = 0;
		    sym_getchar(sym);
		    scc = *sym->ch;
		    sym_getchar(sym);
		    switch (scc) {
		    case 'a':
			sc = '\a';
			break;
		    case 'b':
			sc = '\b';
			break;
		    case 'e':
			sc = '\033';
			break;
		    case 't':
			sc = '\t';
			break;
		    case 'n':
			sc = '\n';
			break;
		    case 'v':
			sc = '\v';
			break;
		    case 'f':
			sc = '\f';
			break;
		    case 'r':
			sc = '\r';
			break;
		    case '\\':
			sc = '\\';
			break;
		    case '"':
			sc = '"';
			break;
		    case '0':
		    case '1':
		    case '2':
		    case '3':
		    case '4':
		    case '5':
		    case '6':
		    case '7':
			sc = scc - '0';
			if (*sym->ch >= '0' && *sym->ch <= '7') {
			    sc <<= 3;
			    sc |= (*sym->ch - '0');
			    sym_getchar(sym);
			    if (*sym->ch >= '0' && *sym->ch <= '7') {
				sc <<= 3;
				sc |= (*sym->ch - '0');
				sym_getchar(sym);
			    }
			}
			break;
		    default:
			report_cfg_error(LOG_INFO, ~0, "Unknown escape sequence '\\%c'", scc);
			continue;
		    }
		    buf_add(sym, sc);
		    continue;
		}
		for (i = 0; i < sym->chlen; i++)
		    buf_add(sym, sym->ch[i]);
		sym_getchar(sym);
	    }
	    buf_add(sym, 0);
	    sym->code = S_string;
	    sym->quoted = 1;
	    sym_getchar(sym);
	    substitute_envvar(sym);
	    return;
	case '/':
	    if (sym->flag_parse_pcre) {
#if defined(WITH_PCRE) || defined(WITH_PCRE2)
		sym_start(sym);
		sym_getchar(sym);
		while (*sym->ch != '/') {
		    switch (*(sym->ch)) {
		    case CHAREOF:
			parse_error(sym, "EOF unexpected");
		    case '\r':
		    case '\n':
			parse_error(sym, "EOL unexpected");
		    case '\\':
			sym_getchar(sym);
			if (*sym->ch != '\\' && *sym->ch != '/')
			    buf_add(sym, '\\');
		    }
		    buf_add(sym, *sym->ch);
		    sym_getchar(sym);
		}
		buf_add(sym, 0);
		sym->code = S_slash;
		sym_getchar(sym);
		return;
#else
		parse_error(sym, "You're using PCRE syntax, but this binary wasn't compiled with PCRE support.");
#endif
	    }
	    /* Fallthrough */
	default:
	    sym_start(sym);
	    while (1)
		switch (*(sym->ch)) {
		case CHAREOF:
		case ' ':
		case '\t':
		case '\r':
		case '\n':
		case '=':
		case '{':
		case '}':
		case '(':
		case ')':
		case '[':
		case ']':
		case '|':
		case '&':
		case '!':
		case ',':
		    buf_add(sym, 0);
		    sym->code = keycode(sym->buf);
		    return;
		default:
		    {
			int i;
			for (i = 0; i < sym->chlen; i++)
			    buf_add(sym, sym->ch[i]);
			sym_getchar(sym);
		    }
		}
	}
}

void buf_add(struct sym *sym, char c)
{
    if (sym->pos >= (int) sizeof(sym->buf)) {
	sym->buf[sizeof(sym->buf) - 1] = '\0';
	parse_error(sym, "Line too long: sym=[%s%s%s] buf='%s%.*s%s'",
		    common_data.font_red, codestring[sym->code], common_data.font_plain, sym->pos, common_data.font_blue, sym->buf, common_data.font_plain);
    }
    sym->buf[sym->pos++] = c;
}

static struct sym *globerror_sym = NULL;
static int globerror(const char *epath, int eerrno)
{
    report_cfg_error(LOG_ERR, ~0, "%s:%u: glob(%s): %s", globerror_sym->filename, globerror_sym->line, epath, strerror(eerrno));
    return 0;
}

static void sym_from_file(struct sym *sym, char *url, struct sym *nsym)
{
    char *buf;
    int buflen;

    memset(sym, 0, sizeof(struct sym));
    sym->filename = strdup(url);
    sym->line = 0;
    sym->next = nsym;

    if (cfg_open_and_read(url, &buf, &buflen)) {
	report_cfg_error(LOG_ERR, ~0, "Couldn't open %s: %s", url, strerror(errno));
	for (; sym; sym = sym->next)
	    report_cfg_error(LOG_ERR, ~0,
			     "file=%s line=%u sym=[%s%s%s] buf='%s%s%s'",
			     sym->filename ? sym->filename : "(unset)",
			     sym->line, common_data.font_red,
			     codestring[sym->code], common_data.font_plain, common_data.font_blue, sym->buf, common_data.font_plain);
	report_cfg_error(LOG_ERR, ~0, "Exiting.");
	exit(EX_NOINPUT);
    }

    sym->tlen = sym->len = buflen;
    sym->tin = sym->in = buf;

    sym_getchar(sym);
}

static void sym_prepend_file(struct sym *sym, char *url)
{
    struct sym *nsym = calloc(1, sizeof(struct sym));
    memcpy(nsym, sym, sizeof(struct sym));
    sym_from_file(sym, url, nsym);
    memcpy(sym->env, nsym->env, sizeof(jmp_buf));
}

struct token_list {
    enum token code;
    int line;
    struct token_list *next;
    char *filename;
    char buf[1];
};

struct token_chain {
    struct token_list *list;
    struct token_chain *next;
};

struct alias {
    struct token_list *list;
    char *filename;
    int line;
    char name[1];
};

static rb_tree_t *aliastable = NULL;

void sym_get(struct sym *sym)
{
    if (sym->token_chain) {
	struct token_list *token_list = sym->token_chain->list;
	strncpy(sym->buf, token_list->buf, sizeof(sym->buf));
	sym->code = token_list->code;
	report_cfg_error(LOG_DEBUG, DEBUG_PARSE_FLAG,
			 "file=%s line=%u sym=[%s%s%s] buf='%s%s%s' (alias)",
			 token_list->filename ? token_list->filename : "(unset)", token_list->line,
			 common_data.font_red, codestring[sym->code], common_data.font_plain, common_data.font_blue, token_list->buf, common_data.font_plain);
	sym->token_chain->list = sym->token_chain->list->next;
	if (!sym->token_chain->list) {
	    struct token_chain *chain = sym->token_chain->next;
	    free(sym->token_chain);
	    sym->token_chain = chain;
	}
    } else {
	getsym(sym);
	report_cfg_error(LOG_DEBUG, DEBUG_PARSE_FLAG,
			 "file=%s line=%u sym=[%s%s%s] buf='%s%s%s'",
			 sym->filename ? sym->filename : "(unset)",
			 sym->line, common_data.font_red,
			 codestring[sym->code], common_data.font_plain, common_data.font_blue, sym->buf, common_data.font_plain);
    }

    if (aliastable && sym->code == S_string) {
	int len = strlen(sym->buf);
	struct alias *a = alloca(sizeof(struct alias) + len);
	memcpy(a->name, sym->buf, len + 1);
	a = RB_lookup(aliastable, (void *) a);
	if (a) {
	    struct token_chain *chain = calloc(1, sizeof(struct token_chain));
	    chain->list = a->list;
	    chain->next = sym->token_chain;
	    sym->token_chain = chain;
	    sym_get(sym);
	    return;
	}
    }

    if (sym->code == S_openbra) {
	long long b = common_data.regex_match_case & 1LL;
	common_data.regex_match_case <<= 1;
	common_data.regex_match_case |= b;
	return;
    }
    if (sym->code == S_closebra) {
	common_data.regex_match_case >>= 1;
	if (common_data.regex_match_case & 1LL) {
#ifdef WITH_PCRE
	    common_data.regex_pcre_flags = PCRE_CASELESS;
#endif
#ifdef WITH_PCRE2
	    common_data.regex_pcre_flags = PCRE2_CASELESS | PCRE2_UTF;
#endif
	    common_data.regex_posix_flags = REG_ICASE;
	} else {
#ifdef WITH_PCRE
	    common_data.regex_pcre_flags = 0;
#endif
#ifdef WITH_PCRE2
	    common_data.regex_pcre_flags = 0;
#endif
	    common_data.regex_posix_flags = 0;
	}
	return;
    }
    if (sym->code == S_regex_match_case) {
	sym_get(sym);
	parse(sym, S_equal);
	int b = parse_bool(sym);
	if (b) {
	    common_data.regex_match_case &= ~1LL;
#ifdef WITH_PCRE
	    common_data.regex_pcre_flags = 0;
#endif
#ifdef WITH_PCRE2
	    common_data.regex_pcre_flags = 0;
#endif
	    common_data.regex_posix_flags = 0;
	} else {
	    common_data.regex_match_case |= 1UL;
#ifdef WITH_PCRE
	    common_data.regex_pcre_flags = PCRE_CASELESS;
#endif
#ifdef WITH_PCRE2
	    common_data.regex_pcre_flags = PCRE2_CASELESS | PCRE2_UTF;
#endif
	    common_data.regex_posix_flags = REG_ICASE;
	}
    }
    if (sym->code == S_include && !sym->flag_prohibit_include) {
	glob_t globbuf;
	char *sb;
	int i;

	memset(&globbuf, 0, sizeof(globbuf));
	sym_get(sym);
	parse(sym, S_equal);
	sb = alloca(strlen(sym->buf) + 1);
	strcpy(sb, sym->buf);
	globerror_sym = sym;
	switch (glob(sb, GLOB_ERR | GLOB_NOESCAPE | GLOB_NOMAGIC | GLOB_BRACE, globerror, &globbuf)) {
	case 0:
	    for (i = (int) globbuf.gl_pathc - 1; i > -1; i--)
		sym_prepend_file(sym, globbuf.gl_pathv[i]);
	    sym_get(sym);
	    break;
#ifdef GLOB_NOMATCH
	case GLOB_NOMATCH:
	    globerror(sb, ENOENT);
	    break;
#endif				/* GLOB_NOMATCH */
	default:
	    sym_prepend_file(sym, sb);
	    sym_get(sym);
	}
	globfree(&globbuf);
    }
    if (sym->code == S_eof && sym->next) {
	struct sym *nsym = sym->next;
	if (sym->filename) {
	    cfg_close(sym->filename, sym->in, sym->len);
	    free(sym->filename);
	}
	memcpy(sym, nsym, sizeof(struct sym));
	sym->next = nsym->next;
	free(nsym);
	sym_get(sym);
    }
}

enum token sym_peek(struct sym *sym)
{
    struct sym mysym;
    memcpy(&mysym, sym, sizeof(struct sym));
    sym_get(&mysym);
    return mysym.code;
}

#ifdef WITH_IPC
#include <sys/ipc.h>
#include <sys/shm.h>

void ipc_delete(void)
{
    if (common_data.ipc_key) {
	int id = shmget((key_t) common_data.ipc_key, 0, 0);
	if (id != -1)
	    shmctl(id, IPC_RMID, NULL);
    }
}

int ipc_create(char *buf, int buflen)
{
    int id;
    char *s;
    char u[80];

    if (!common_data.ipc_key)
	return -1;

    id = shmget((key_t) common_data.ipc_key, 0, 0);
    if (id != -1)
	shmctl(id, IPC_RMID, NULL);

    id = shmget((key_t) common_data.ipc_key, (size_t) buflen, IPC_CREAT | 0600);
    if (id < 0)
	return -1;

    s = shmat(id, NULL, 0);
    if (s == (char *) -1)
	return -1;

    memcpy(s, buf, buflen);
    s[buflen] = 0;
    snprintf(u, sizeof(u), "ipc://%lu/%lu", (u_long) common_data.ipc_key, (u_long) buflen);
    common_data.ipc_url = strdup(u);
    return 0;
}

static int ipc_open_and_read(char *url, char **buf, int *buflen)
{
    int id;
    char *s;
    u_long key;
    u_long len;

    if (2 != sscanf(url, "ipc://%lu/%lu", &key, &len)) {
	errno = ENOENT;
	return -1;
    }

    id = shmget((key_t) key, (size_t) len, 0400);
    if (id < 0)
	return -1;

    s = shmat(id, NULL, 0);
    if (s == (char *) -1)
	return -1;

    *buf = s;
    *buflen = (int) len;

    return 0;
}
#endif

#ifdef WITH_CURL
#include <curl/curl.h>

struct curl_write_cb_data {
    char *buf;
    size_t size;
    size_t maxsize;
};

static size_t curl_write_cb(void *ptr, size_t size, size_t nmemb, void *stream)
{
    struct curl_write_cb_data *cd = (struct curl_write_cb_data *) stream;
    if (!cd->maxsize) {
	cd->maxsize = CURL_MAX_WRITE_SIZE;
	cd->buf = calloc(1, cd->maxsize);
    } else if (cd->size + CURL_MAX_WRITE_SIZE > cd->maxsize) {
	cd->maxsize += CURL_MAX_WRITE_SIZE;
	cd->buf = realloc(cd->buf, cd->maxsize);
    }

    memcpy(cd->buf + cd->size, ptr, size * nmemb);
    cd->size += size * nmemb;
    return size * nmemb;
}

static int curl_open_and_read(char *url, char **buf, int *buflen)
{
    CURL *curl = curl_easy_init();

    if (curl) {
	struct curl_write_cb_data *cd = calloc(1, sizeof(struct curl_write_cb_data));
	CURLcode res;
	FILE *devnull = fopen("/dev/null", "r");
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_TRANSFERTEXT, 1L);
	curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
	curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
#ifndef CURLOPT_WRITEDATA
#define CURLOPT_WRITEDATA CURLOPT_FILE
#endif
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, cd);
	curl_easy_setopt(curl, CURLOPT_STDERR, devnull);
	res = curl_easy_perform(curl);
	curl_easy_cleanup(curl);
	fclose(devnull);
	*buf = cd->buf;
	*buflen = cd->size;
	if (res)
	    errno = ENOENT;
	return res;
    }
    return -1;
}
#endif

static int mmap_open_and_read(char *url, char **buf, int *buflen)
{
    struct stat st;
    int fn = open(url, O_RDONLY);
    if (fn < 0)
	return -1;
    if (fstat(fn, &st) || !S_ISREG(st.st_mode)) {
	close(fn);
	errno = ENOENT;
	return -1;
    }
    *buflen = (int) st.st_size;
    *buf = (char *) mmap(0, (size_t) (st.st_size), PROT_READ, MAP_SHARED, fn, 0);
    close(fn);
    return 0;
}

int cfg_open_and_read(char *url, char **buf, int *buflen)
{
#define CFG_FILE 0
#define CFG_IPC 1
#define CFG_CURL 2
    int cfgloc = CFG_FILE;

#ifdef WITH_IPC
    if (!strncmp(url, "ipc://", 6))
	cfgloc = CFG_IPC;
#endif
#ifdef WITH_CURL
#ifdef WITH_IPC
    else
#endif
    if (strstr(url, "://"))
	cfgloc = CFG_CURL;
#endif

    switch (cfgloc) {
#ifdef WITH_IPC
    case CFG_IPC:
	if (!ipc_open_and_read(url, buf, buflen))
	    return 0;
	break;
#endif
#ifdef WITH_CURL
    case CFG_CURL:
	if (!curl_open_and_read(url, buf, buflen))
	    return 0;
	break;
#endif
    case CFG_FILE:
	if (!mmap_open_and_read(url, buf, buflen))
	    return 0;
	break;
    }
    return -1;
}

int cfg_close(char *url __attribute__((unused)), char *buf, int buflen)
{
    int cfgloc = CFG_FILE;

#ifdef WITH_IPC
    if (!strncmp(url, "ipc://", 6))
	cfgloc = CFG_IPC;
#endif
#ifdef WITH_CURL
#ifdef WITH_IPC
    else
#endif
    if (strstr(url, "://"))
	cfgloc = CFG_CURL;
#endif

    switch (cfgloc) {
#ifdef WITH_IPC
    case CFG_IPC:
	return shmdt(buf);
#endif
#ifdef WITH_CURL
    case CFG_CURL:
	free(buf);
	return 0;
#endif
    case CFG_FILE:
	return munmap(buf, (size_t) buflen);
    }
    return -1;
}

static void clear_alias(void);

void cfg_read_config(char *url, void (*parsefunction)(struct sym *), char *id)
{
    struct sym sym;
    int found, buflen;
    char *buf;

    clear_alias();
    memset(&sym, 0, sizeof(sym));
    sym.filename = url;
    sym.line = 0;

    sym.env_valid = 1;
    if (setjmp(sym.env)) {
	struct scm_data sd;
	memset(&sd, 0, sizeof(sd));
	sd.type = SCM_BAD_CFG;
	common_data.scm_send_msg(0, &sd, -1);
	report_cfg_error(LOG_ERR, ~0, "Detected fatal configuration error. Exiting.");
	exit(EX_CONFIG);
    }

    found = 0;

    if (cfg_open_and_read(url, &buf, &buflen)) {
	report_cfg_error(LOG_ERR, ~0, "Couldn't open %s: %s", url, strerror(errno));
	report_cfg_error(LOG_ERR, ~0, "Exiting.");
	exit(EX_NOINPUT);
    }

    sym.tlen = sym.len = buflen;
    sym.tin = sym.in = buf;

    sym_init(&sym);
    while (sym.code != S_eof) {
	switch (sym.code) {
	case S_id:
	    sym_get(&sym);
	    parse(&sym, S_equal);
	    if (strcmp(sym.buf, id)) {
		int bc = 1;
		sym_get(&sym);
		parse(&sym, S_openbra);
		while (bc) {
		    switch (sym.code) {
		    case S_openbra:
			bc++;
			break;
		    case S_closebra:
			bc--;
			break;
		    case S_eof:
			parse_error(&sym, "EOF unexpected");
		    default:
			;
		    }
		    sym_get(&sym);
		}
	    } else {
		found = 1;
		sym_get(&sym);
		parse(&sym, S_openbra);
		parsefunction(&sym);
		parse(&sym, S_closebra);
	    }
	    break;
	case S_eof:
	    break;
	case S_alias:
	case S_trace:
	case S_debug:
	case S_syslog:
	case S_proctitle:
	case S_coredump:
	case S_gcore:
	case S_debug_cmd:
	case S_setenv:
	    parse_common(&sym);
	    break;
	default:
	    parse_error_expect(&sym, S_alias, S_id, S_debug, S_trace, S_syslog, S_proctitle, S_gcore, S_debug_cmd, S_unknown);

	}
    }

    cfg_close(url, buf, buflen);
    fflush(stderr);

    if (!found) {
	report_cfg_error(LOG_ERR, ~0, "%s:%u: FATAL: No configuration for id '%s' found.", sym.filename, sym.line, id);
	exit(EX_CONFIG);
    }
}

enum token keycode(char *keyword)
{
    int mid, len = S_null, start = 0, i;

    do {
	mid = len / 2;
	i = strcmp(keyword, codestring[start + mid]);
	if (i < 0)
	    len = mid;
	else if (!i) {
	    return (enum token) (start + mid);
	} else
	    start += mid, len -= mid;
    }
    while (mid);
    return S_string;
}

int parse_int(struct sym *sym)
{
    int i;
    char c;

    switch (sscanf(sym->buf, "%d%c", &i, &c)) {
    case 2:
	switch (c) {
	default:
	    goto bye;
	case 'g':
	case 'G':
	    i <<= 10;
	case 'm':
	case 'M':
	    i <<= 10;
	case 'k':
	case 'K':
	    i <<= 10;
	}
    case 1:
	sym_get(sym);
	return i;
    default:
      bye:
	parse_error(sym, "expected an integer, but got '%s'", sym->buf);
	return -1;
    }
}

int parse_seconds(struct sym *sym)
{
    int i;
    char c;

    switch (sscanf(sym->buf, "%d%c", &i, &c)) {
    case 2:
	switch (c) {
	default:
	    goto bye;
	case 'd':
	case 'D':
	    i *= 24;
	case 'h':
	case 'H':
	    i *= 60;
	case 'm':
	case 'M':
	    i *= 60;
	case 's':
	case 'S':
	    ;
	}
    case 1:
	sym_get(sym);
	return i;
    default:
      bye:
	parse_error(sym, "expected an integer, but got '%s'", sym->buf);
	return -1;
    }
}

void sym_init(struct sym *sym)
{
    sym_getchar(sym);
    sym_get(sym);
}

void report_cfg_error(int priority, int level, char *fmt, ...)
{
    int len = 1024;
    char *msg = alloca(len);
    va_list ap;
    int nlen;

    va_start(ap, fmt);
    nlen = vsnprintf(msg, len, fmt, ap);
    va_end(ap);
    if (len <= nlen) {
	msg = alloca(++nlen);
	va_start(ap, fmt);
	vsnprintf(msg, nlen, fmt, ap);
	va_end(ap);
    }

    if ((common_data.debug & level) /*|| common_data.parse_only */ ) {
	if (common_data.debugtty)
	    fprintf(stderr, "%ld: %s\n", (long int) common_data.pid, msg);
	else
	    syslog(LOG_DEBUG, "%s%s", (priority & LOG_PRIMASK) == LOG_ERR ? "Error " : "", msg);
    }
    priority &= LOG_PRIMASK;

    if (priority != LOG_DEBUG) {
	if (common_data.parse_only)
	    fprintf(stderr, "%ld: %s\n", (long int) common_data.pid, msg);
	else
	    syslog(priority, "%s%s", priority == LOG_ERR ? "Error " : "", msg);
    }

}

void parse_debug(struct sym *sym, u_int * d)
{
    int bit, add = ~0;
    while (sym->code != S_eof) {
	switch (sym->code) {
	case S_string:
	    if (isdigit((int) (sym->buf[0]))
		|| ((sym->buf[0] == '-')
		    && isdigit((int) (sym->buf[1])))) {
		*d |= parse_int(sym);
		*d &= DEBUG_ALL_FLAG;
		continue;
	    }
	    switch (sym->buf[0]) {
	    case '-':
		add = 0;
		break;
	    case '+':
		add = ~0;
		break;
	    default:
		return;
	    }
	    sym->code = keycode(sym->buf + 1);
	    if (sym->code == S_string)
		return;
	    continue;
	case S_PARSE:
	    bit = DEBUG_PARSE_FLAG;
	    break;
	case S_AUTHOR:
	    bit = DEBUG_AUTHOR_FLAG;
	    break;
	case S_AUTHEN:
	    bit = DEBUG_AUTHEN_FLAG;
	    break;
	case S_ACCT:
	    bit = DEBUG_ACCT_FLAG;
	    break;
	case S_CONFIG:
	    bit = DEBUG_CONFIG_FLAG;
	    break;
	case S_PACKET:
	    bit = DEBUG_PACKET_FLAG;
	    break;
	case S_HEX:
	    bit = DEBUG_HEX_FLAG;
	    break;
	case S_LOCK:
	    bit = DEBUG_LOCK_FLAG;
	    break;
	case S_REGEX:
	    bit = DEBUG_REGEX_FLAG;
	    break;
	case S_ACL:
	    bit = DEBUG_ACL_FLAG;
	    break;
	case S_CMD:
	    bit = DEBUG_CMD_FLAG;
	    break;
	case S_NET:
	    bit = DEBUG_NET_FLAG;
	    break;
	case S_PATH:
	    bit = DEBUG_PATH_FLAG;
	    break;
	case S_CONTROL:
	    bit = DEBUG_CONTROL_FLAG;
	    break;
	case S_INDEX:
	    bit = DEBUG_INDEX_FLAG;
	    break;
	case S_AV:
	    bit = DEBUG_AV_FLAG;
	    break;
	case S_MAVIS:
	    bit = DEBUG_MAVIS_FLAG;
	    break;
	case S_BUFFER:
	    bit = DEBUG_BUFFER_FLAG;
	    break;
	case S_PROC:
	    bit = DEBUG_PROC_FLAG;
	    break;
	case S_LWRES:
	    bit = DEBUG_LWRES_FLAG;
	    break;
	case S_USERINPUT:
	    bit = DEBUG_USERINPUT_FLAG;
	    break;
	case S_NONE:
	    if (add) {
		bit = DEBUG_NONE_FLAG;
		*d = 0;
		break;
	    } else
		add = 1;
	    // fallthrough
	case S_ALL:
	    bit = DEBUG_ALL_FLAG;
	    break;
	default:
	    if ((*d & DEBUG_NONE_FLAG) != *d)
		*d &= ~DEBUG_NONE_FLAG;
	    return;
	}
	if (add)
	    *d |= bit;
	else
	    *d &= ~bit, add = 1;

	sym_get(sym);
    }
}

struct searchpath {
    struct searchpath *next;
    char dir[1];
};

static struct searchpath *mavis_searchpath = NULL;

void parse_mavispath(struct sym *sym)
{
    char buf[MAX_INPUT_LINE_LEN];
    struct searchpath **sp = &mavis_searchpath;
    while ((*sp))
	sp = &((*sp)->next);
    sym_get(sym);		// S_path
    parse(sym, S_equal);
    ostypef(sym->buf, buf, sizeof(buf));
    *sp = calloc(1, sizeof(struct searchpath) + strlen(buf));
    strcpy((*sp)->dir, buf);
    sym_get(sym);
}

static int mavis_method_addf(mavis_ctx ** mcx, struct io_context *ioctx, char *id, char *fmt, ...)
{
    int len = 1024, nlen;
    char *p = alloca(len);
    va_list ap;

    va_start(ap, fmt);
    nlen = vsnprintf(p, len, fmt, ap);
    va_end(ap);
    if (len <= nlen) {
	p = alloca(++nlen);
	va_start(ap, fmt);
	vsnprintf(p, nlen, fmt, ap);
	va_end(ap);
    }
    return mavis_method_add(mcx, ioctx, p, id);
}


int parse_mavismodule(mavis_ctx ** mcx, struct io_context *ioctx, struct sym *sym)
{
    char *identity_source_name = NULL;
    mavis_ctx *m;
    int res = -1;
    static int i = 0;
    char id[10];
    snprintf(id, 10, "%d", i++);

    sym_get(sym);		//S_module
    if (sym->code != S_equal) {	// identity_source_name
	identity_source_name = strdup(sym->buf);
	sym_get(sym);
    }
    parse(sym, S_equal);
    /* sym->buf is the module name, might be an absolute path */
    if (sym->buf[0] == '/') {
	char buf[MAX_INPUT_LINE_LEN];
	ostypef(sym->buf, buf, sizeof(buf));
	res = mavis_method_addf(mcx, ioctx, id, "%s", buf);
    } else {
	if (mavis_searchpath) {
	    struct searchpath *sp = mavis_searchpath;
	    while (sp) {
		res = mavis_method_addf(mcx, ioctx, id, "%s/libmavis_%s.so", sp->dir, sym->buf);
		if (!res)
		    break;
		sp = sp->next;
	    }
	} else {
	    static char *bp = NULL;
	    if (!bp) {
		get_exec_path(&bp, "");
		if (*bp) {
		    char *s = bp + strlen(bp);
		    while (s > bp && *s != '/')
			*s-- = 0;
		    while (s > bp && *s == '/')
			*s-- = 0;
		    while (s > bp && *s != '/')
			*s-- = 0;
		    while (s > bp && *s == '/')
			*s-- = 0;
		    if (s > bp)
			res = mavis_method_addf(mcx, ioctx, id, "%s/lib/mavis/libmavis_%s.so", bp, sym->buf);
		}
	    }
#ifdef MAVIS_DIR
	    if (res)
		res = mavis_method_addf(mcx, ioctx, id, MAVIS_DIR "/libmavis_%s.so", sym->buf);
#endif
	}
    }

    m = *mcx;
    while (m->down)
	m = m->down;
    m->identity_source_name = identity_source_name ? identity_source_name : strdup(m->identifier);

    if (res) {
	report_cfg_error(LOG_ERR, ~0, "%s:%u: FATAL: module '%s' not found.", sym->filename, sym->line, sym->buf);
	return -1;
    }

    sym_get(sym);

    parse(sym, S_openbra);
    if (mavis_parse(*mcx, sym, id) != MAVIS_CONF_OK)
	return -1;
    parse(sym, S_closebra);
    return 0;
}

void parse_userid(struct sym *sym, uid_t * uid, gid_t * gid)
{
    sym_get(sym);
    parse(sym, S_equal);
    if (isdigit((int) (sym->buf[0])))
	*uid = (uid_t) parse_int(sym);
    else {
	struct passwd *pw = getpwnam(sym->buf);
	if (!pw)
	    parse_error(sym, "UNIX user '%s' not found.", sym->buf);
	*uid = pw->pw_uid;
	if (gid)
	    *gid = pw->pw_gid;
	sym_get(sym);
    }
}

void parse_groupid(struct sym *sym, gid_t * gid)
{
    sym_get(sym);
    parse(sym, S_equal);
    if (isdigit((int) (sym->buf[0])))
	*gid = (gid_t) parse_int(sym);
    else {
	struct group *gr = getgrnam(sym->buf);
	if (!gr)
	    parse_error(sym, "UNIX group '%s' not found.", sym->buf);
	*gid = gr->gr_gid;
	sym_get(sym);
    }

}

void parse_umask(struct sym *sym, mode_t * m)
{
    u_int i;
    sym_get(sym);
    parse(sym, S_equal);
    if (1 != sscanf(sym->buf, "%o", &i))
	parse_error(sym, "Unrecognized file node creation mask '%s'", sym->buf);
    sym_get(sym);
    *m = (mode_t) i;
}

struct a2n {
    char *a;
    int n;
};

static struct a2n loglevels[] = {
#ifdef LOG_EMERG
    { "EMERG", LOG_EMERG, },
#endif
#ifdef LOG_ALERT
    { "ALERT", LOG_ALERT, },
#endif
#ifdef LOG_CRIT
    { "CRIT", LOG_CRIT, },
#endif
#ifdef LOG_ERR
    { "ERR", LOG_ERR, },
#endif
#ifdef LOG_WARNING
    { "WARNING", LOG_WARNING, },
#endif
#ifdef LOG_NOTICE
    { "NOTICE", LOG_NOTICE, },
#endif
#ifdef LOG_INFO
    { "INFO", LOG_INFO, },
#endif
#ifdef LOG_DEBUG
    { "DEBUG", LOG_DEBUG, },
#endif
    { NULL, 0, }
};

static struct a2n logfacilities[] = {
#ifdef LOG_AUTH
    { "AUTH", LOG_AUTH, },
#endif
#ifdef LOG_AUTHPRIV
    { "AUTHPRIV", LOG_AUTHPRIV, },
#endif
#ifdef LOG_CRON
    { "CRON", LOG_CRON, },
#endif
#ifdef LOG_DAEMON
    { "DAEMON", LOG_DAEMON, },
#endif
#ifdef LOG_KERN
    { "KERN", LOG_KERN, },
#endif
#ifdef LOG_LOCAL0
    { "LOCAL0", LOG_LOCAL0, },
#endif
#ifdef LOG_LOCAL1
    { "LOCAL1", LOG_LOCAL1, },
#endif
#ifdef LOG_LOCAL2
    { "LOCAL2", LOG_LOCAL2, },
#endif
#ifdef LOG_LOCAL3
    { "LOCAL3", LOG_LOCAL3, },
#endif
#ifdef LOG_LOCAL4
    { "LOCAL4", LOG_LOCAL4, },
#endif
#ifdef LOG_LOCAL5
    { "LOCAL5", LOG_LOCAL5, },
#endif
#ifdef LOG_LOCAL6
    { "LOCAL6", LOG_LOCAL6, },
#endif
#ifdef LOG_LOCAL7
    { "LOCAL7", LOG_LOCAL7, },
#endif
#ifdef LOG_LPR
    { "LPR", LOG_LPR, },
#endif
#ifdef LOG_MAIL
    { "MAIL", LOG_MAIL, },
#endif
#ifdef LOG_NEWS
    { "NEWS", LOG_NEWS, },
#endif
#ifdef LOG_SYSLOG
    { "SYSLOG", LOG_SYSLOG, },
#endif
#ifdef LOG_USER
    { "USER", LOG_USER, },
#endif
#ifdef LOG_UUCP
    { "UUCP", LOG_UUCP, },
#endif
#ifdef LOG_FTP
    { "FTP", LOG_FTP, },
#endif
    { NULL, 0, }
};

int get_syslog_level(char *s)
{
    struct a2n *l;
    for (l = loglevels; l->a; l++)
	if (!strcasecmp(l->a, s))
	    return l->n;
    return 0;
}

int get_syslog_facility(char *s)
{
    struct a2n *l;
    for (l = logfacilities; l->a; l++)
	if (!strcasecmp(l->a, s))
	    return l->n;
    return 0;
}

static void parse_syslog(struct sym *sym)
{
    sym_get(sym);
    switch (sym->code) {
    case S_level:
	sym_get(sym);
	parse(sym, S_equal);
	common_data.syslog_level = get_syslog_level(sym->buf);
	sym_get(sym);
	break;
    case S_facility:
	sym_get(sym);
	parse(sym, S_equal);
	common_data.syslog_facility = get_syslog_facility(sym->buf);
	sym_get(sym);
	break;
    case S_ident:
	sym_get(sym);
	parse(sym, S_equal);
	common_data.syslog_ident = strdup(sym->buf);
	sym_get(sym);
	break;
    case S_default:
	sym_get(sym);
	parse(sym, S_equal);
	common_data.syslog_dflt = parse_bool(sym) ? 1 : 0;
	break;
    default:
	parse_error_expect(sym, S_level, S_facility, S_ident, S_default, S_unknown);
    }
    logopen();
}

void add_token_to_alias(struct token_list **p, struct sym *sym)
{
    struct token_list *n;
    int len;
    while (*p)
	p = &(*p)->next;
    len = strlen(sym->buf);
    n = calloc(1, sizeof(struct alias) + len);
    n->code = sym->code;
    memcpy(n->buf, sym->buf, len + 1);
    n->line = sym->line;
    n->filename = sym->filename;
    *p = n;
}

static int compare_alias(const void *a, const void *b)
{
    return strcmp(((struct alias *) a)->name, ((struct alias *) b)->name);
}

static void free_alias(void *p)
{
    struct token_list *n = ((struct alias *) p)->list;
    while (n) {
	struct token_list *m = n->next;
	free(n);
	n = m;
    }
    free(p);
}

struct token_list **add_alias(char *name)
{
    int len = strlen(name);
    struct alias *a = calloc(1, sizeof(struct alias) + len);
    memcpy(a->name, name, len + 1);
    if (!aliastable)
	aliastable = RB_tree_new(compare_alias, free_alias);
    RB_insert(aliastable, a);
    return &a->list;
}

static void clear_alias(void)
{
    RB_tree_delete(aliastable);
    aliastable = NULL;
}

static void parse_alias(struct sym *sym)
{
    struct token_list **p = NULL;
    int bc = 1;
    sym_get(sym);
    if (sym->code == S_equal)
	sym_get(sym);
    p = add_alias(sym->buf);
    sym_get(sym);
    parse(sym, S_openbra);
    while (bc && sym->code != S_eof) {
	switch (sym->code) {
	case S_openbra:
	    bc++;
	    break;
	case S_closebra:
	    bc--;
	default:
	    break;
	}
	if (bc)
	    add_token_to_alias(p, sym);
	sym_get(sym);
    }
}

void parse_common(struct sym *sym)
{
    switch (sym->code) {
    case S_trace:
    case S_debug:
	sym_get(sym);
	switch (sym->code) {
	case S_redirect:
	    sym_get(sym);
	    parse(sym, S_equal);
	    if (freopen(sym->buf, "w+", stderr)) {
		common_data.debug_redirected = 1;
		common_data.font_blue = "";
		common_data.font_red = "";
		common_data.font_plain = "";
		common_data.font_bold = "";
	    }
	    sym_get(sym);
	    break;
	case S_equal:
	    sym_get(sym);
	    parse_debug(sym, &common_data.debug);
	    break;
	default:
	    parse_error_expect(sym, S_redirect, S_equal, S_unknown);
	}
	break;
    case S_alias:
	parse_alias(sym);
	break;
    case S_syslog:
	parse_syslog(sym);
	break;
    case S_proctitle:
	sym_get(sym);
	parse(sym, S_equal);
	strset(&common_data.proctitle, sym->buf);
	sym_get(sym);
	break;
    case S_coredump:
	sym_get(sym);
	parse(sym, S_directory);
	parse(sym, S_equal);
	strset(&common_data.coredumpdir, sym->buf);
	sym_get(sym);
	break;
    case S_gcore:
	sym_get(sym);
	parse(sym, S_equal);
	common_data.gcorepath = strdup(sym->buf);
	sym_get(sym);
	break;
    case S_debug_cmd:
	sym_get(sym);
	parse(sym, S_equal);
	strset(&common_data.debug_cmd, sym->buf);
	sym_get(sym);
	break;
    case S_setenv:{
	    char *e;
	    sym_get(sym);
	    e = alloca(strlen(sym->buf) + 1);
	    strcpy(e, sym->buf);
	    sym_get(sym);
	    if (sym->code == S_equal)
		sym_get(sym);
	    setenv(e, sym->buf, 1);
	    sym_get(sym);
	    break;
	}
    default:
	parse_error_expect(sym, S_alias, S_debug, S_trace, S_syslog, S_proctitle, S_coredump, S_gcore, S_debug_cmd, S_setenv, S_unknown);
    }
}

void common_usage(void)
{
    fprintf(stderr,
	    "%sUsage:%s %s%s%s [ <%sOptions%s> ] <%sconfiguration file%s> [ <%sid%s> ]\n"
	    "\n"
	    "%sOptions:%s\n"
	    "-P                parse configuration file, then quit\n"
	    "-1                enable single-process (\"degraded\") mode\n"
	    "-v                show version, then quit\n"
	    "-b                force going to background\n"
	    "-f                force staying in foreground\n"
	    "-i <child-id>     select child configuration id\n"
	    "-I <spawnd-id>    select spawnd configuration id\n"
	    "-p <pid-file>     write master process ID to the file specified\n"
	    "-d <debug-level>  set debugging level\n"
	    "\n"
	    "%sVersion:%s %s%s%s\n"
	    "\n"
	    "%sCopyright (C) 1996-2022 by Marc Huber <Marc.Huber@web.de>\n"
	    "Portions Copyright (C) 1995-1998 by Cisco Systems, Inc.%s\n"
	    "\n"
	    "%sSource code and documentation:%s %shttp://www.pro-bono-publico.de/projects/%s\n"
	    "\n"
	    "%sPlease direct support requests either to the \"Event-Driven Servers\" Google Group at\n"
	    "\n"
	    "    event-driven-servers@googlegroups.com\n"
	    "    http://groups.google.com/group/event-driven-servers\n"
	    "\n"
	    "or open an issue at the GitHub page at\n"
	    "\n"
	    "    https://github.com/MarcJHuber/event-driven-servers/issues\n"
	    "\n"
	    "Support requests sent to the author's private email address may be silently\n"
	    "ignored.%s\n"
	    "\n",
	    common_data.font_bold, common_data.font_plain,
	    common_data.font_blue, common_data.progname,
	    common_data.font_plain, common_data.font_blue,
	    common_data.font_plain, common_data.font_blue,
	    common_data.font_plain, common_data.font_blue,
	    common_data.font_plain, common_data.font_bold,
	    common_data.font_plain, common_data.font_bold,
	    common_data.font_plain, common_data.font_blue,
	    common_data.version, common_data.font_plain,
	    common_data.font_bold, common_data.font_plain,
	    common_data.font_bold, common_data.font_plain, common_data.font_blue, common_data.font_plain, common_data.font_red, common_data.font_plain);
    exit(EX_USAGE);
}

struct mavis_cond *mavis_cond_add(struct mavis_cond *a, struct mavis_cond *b)
{
    if (a->u.m.n && !(a->u.m.n & 7))
	a = realloc(a, sizeof(struct mavis_cond) + a->u.m.n * sizeof(struct mavis_cond *));

    a->u.m.e[a->u.m.n] = b;
    a->u.m.n++;
    return a;
}

struct mavis_cond *mavis_cond_new(struct sym *sym, enum token type)
{
    struct mavis_cond *m = calloc(1, sizeof(struct mavis_cond));
    m->type = type;
    m->line = sym->line;
    return m;
}

int sym_normalize_cond_start(struct sym *sym, struct sym **mysym)
{
    if (sym->code == S_leftbra) {
#define SYM_COND_BUFSIZE 40960
	char *buf = calloc(1, SYM_COND_BUFSIZE);
	char *b = buf, *p;
	int bc = 1;
	enum token prev = S_unknown;
#define EC_MAX 1024
	int e[EC_MAX], ec = 0;

	sym_get(sym);		// S_leftbra

	*b++ = '(';
	*b++ = '(';
	*b++ = '(';
	*b++ = '(';
	*b++ = '(';

	while (bc && (b < buf + SYM_COND_BUFSIZE - 100)) {
	    switch (sym->code) {
	    case S_and:
		strcpy(b, ") && (");
		while (*b)
		    b++;
		prev = sym->code;
		sym_get(sym);
		continue;
	    case S_or:
		strcpy(b, ")) || ((");
		while (*b)
		    b++;
		prev = sym->code;
		sym_get(sym);
		continue;
	    case S_leftbra:
		if (prev == S_exclmark) {
		    *b++ = '(';
		    *b++ = '(';
		    *b++ = '(';
		    if (ec < EC_MAX) {
			e[ec++] = bc;
		    } else
			parse_error(sym, "Too many nested negations.");
		}
		*b++ = '(';
		*b++ = '(';
		bc++;
		prev = sym->code;
		sym_get(sym);
		continue;
	    case S_rightbra:
		bc--;
		if (ec > 0 && e[ec - 1] == bc) {
		    *b++ = ')';
		    *b++ = ')';
		    *b++ = ')';
		    ec--;
		}
		*b++ = ')';
		*b++ = ')';
		if (bc == 0) {
		    sym_get(sym);
		    *b++ = ')';
		    *b++ = ')';
		    *b++ = ')';
		    bc = 0;
		    continue;
		}
		prev = sym->code;
		sym_get(sym);
		continue;
	    case S_openbra:
	    case S_closebra:
		if (bc)
		    parse_error(sym, "Got '%s' -- did you omit a ')' somewhere?", codestring[sym->code]);
		prev = sym->code;
		break;
	    case S_tilde:
		sym->flag_parse_pcre = 1;
		break;
	    case S_eof:
		parse_error(sym, "EOF unexpected");
	    default:;
	    }
	    prev = sym->code;
	    *b++ = ' ';

	    for (p = sym->raw; p < sym->tin - 1; p++)
		*b++ = *p;
	    *b = 0;
	    sym_get(sym);
	    sym->flag_parse_pcre = 0;
	}
	while (*b)
	    b++;

	*mysym = calloc(1, sizeof(struct sym));
	memcpy(*mysym, sym, sizeof(struct sym));
	(*mysym)->tlen = (*mysym)->len = (int) (b - buf);
	(*mysym)->tin = (*mysym)->in = buf;
	sym_init(*mysym);
	return -1;
    }
    return 0;
}

void sym_normalize_cond_end(struct sym **mysym)
{
    if (*mysym) {
	if ((*mysym)->in)
	    free((*mysym)->in);
	free(*mysym);
	*mysym = NULL;
    }
}

static struct mavis_cond *mavis_cond_parse_attr_lhs(struct sym *sym, enum token token)
{
    struct mavis_cond *m = mavis_cond_new(sym, token);
    m->u.s.lhs = (void *) (long) av_attr_token_to_i(sym);
    if ((long) m->u.s.lhs < 0)
	parse_error(sym, "'%s' is not a recognized attribute", sym->buf);
    m->u.s.lhs_txt = strdup(sym->buf);
    sym_get(sym);
    return m;
}

static struct mavis_cond *mavis_cond_parse_r(struct sym *sym)
{
    struct mavis_cond *m, *p = NULL;

    switch (sym->code) {
    case S_leftbra:
	sym_get(sym);
	m = mavis_cond_add(mavis_cond_new(sym, S_or), mavis_cond_parse_r(sym));
	if (sym->code == S_and)
	    m->type = S_and;
	while (sym->code == S_and || sym->code == S_or) {
	    sym_get(sym);
	    m = mavis_cond_add(m, mavis_cond_parse_r(sym));
	}
	parse(sym, S_rightbra);
	return m;
    case S_exclmark:
	sym_get(sym);
	m = mavis_cond_add(mavis_cond_new(sym, S_exclmark), mavis_cond_parse_r(sym));
	return m;
    case S_undef:
    case S_defined:{
	    int bracket = 0;
	    enum token sc = sym->code;
	    sym_get(sym);
	    while (sym->code == S_leftbra) {
		bracket++;
		sym_get(sym);
	    }
	    m = mavis_cond_parse_attr_lhs(sym, sc);
	    while (bracket) {
		parse(sym, S_rightbra);
		bracket--;
	    }
	    return m;
	}
    case S_eof:
	parse_error(sym, "EOF unexpected");
    default:
	m = mavis_cond_parse_attr_lhs(sym, S_equal);
	switch (sym->code) {
	case S_exclmark:
	    p = mavis_cond_add(mavis_cond_new(sym, S_exclmark), m);
	case S_equal:
	    break;
	default:
	    parse_error_expect(sym, S_exclmark, S_equal, S_unknown);
	}
	sym_get(sym);
	switch (sym->code) {
	case S_equal:
	    m->type = S_equal;
	    break;
	case S_tilde:
	    m->type = S_regex;
	    sym->flag_parse_pcre = 1;
	    break;
	default:
	    parse_error_expect(sym, S_equal, S_tilde, S_unknown);
	}
	sym_get(sym);
	m->u.s.token = S_unknown;

	if (m->type == S_equal) {
	    if (sym->code == S_string)
		m->u.s.rhs = strdup(sym->buf);
	    else {
		m->u.s.rhs = (void *) (long) av_attr_token_to_i(sym);
		if ((long) m->u.s.rhs < 0)
		    parse_error(sym, "'%s' is not a recognized attribute", sym->buf);
		m->u.s.token = S_attr;
	    }
	    m->u.s.rhs_txt = strdup(sym->buf);
	    sym_get(sym);
	    return p ? p : m;
	} else {
	    int errcode = 0;
	    if (sym->code == S_slash) {
#ifdef WITH_PCRE
		int erroffset;
		const char *errptr;
		m->type = S_slash;
		m->u.s.rhs = pcre_compile2(sym->buf, PCRE_MULTILINE | common_data.regex_pcre_flags, &errcode, &errptr, &erroffset, NULL);
		if (!m->u.s.rhs)
		    parse_error(sym, "In PCRE expression /%s/ at offset %d: %s", sym->buf, erroffset, errptr);
		m->u.s.rhs_txt = strdup(sym->buf);
		sym->flag_parse_pcre = 0;
		sym_get(sym);
		return p ? p : m;
#else
#ifdef WITH_PCRE2
		PCRE2_SIZE erroffset;
		m->type = S_slash;
		m->u.s.rhs =
		    pcre2_compile((PCRE2_SPTR8) sym->buf, PCRE2_ZERO_TERMINATED, PCRE2_MULTILINE | common_data.regex_pcre_flags, &errcode, &erroffset, NULL);
		if (!m->u.s.rhs) {
		    PCRE2_UCHAR buffer[256];
		    pcre2_get_error_message(errcode, buffer, sizeof(buffer));
		    parse_error(sym, "In PCRE2 expression /%s/ at offset %d: %s", sym->buf, erroffset, buffer);
		}
		m->u.s.rhs_txt = strdup(sym->buf);
		sym->flag_parse_pcre = 0;
		sym_get(sym);
		return p ? p : m;
#else
		parse_error(sym, "You're using PCRE syntax, but this binary wasn't compiled with PCRE support.");
#endif
#endif
	    }
	    m->u.s.rhs = calloc(1, sizeof(regex_t));
	    errcode = regcomp((regex_t *) m->u.s.rhs, sym->buf, REG_EXTENDED | REG_NOSUB | REG_NEWLINE | common_data.regex_posix_flags);
	    if (errcode) {
		char e[160];
		regerror(errcode, (regex_t *) m->u.s.rhs, e, sizeof(e));
		parse_error(sym, "In regular expression '%s': %s", sym->buf, e);
	    }
	    m->u.s.rhs_txt = strdup(sym->buf);
	    sym_get(sym);
	    return p ? p : m;
	}
    }
}

void mavis_cond_optimize(struct mavis_cond **m)
{
    struct mavis_cond *p;
    int i;
    while (*m && ((*m)->type == S_or || (*m)->type == S_and)
	   && (*m)->u.m.n == 1) {
	p = *m;
	*m = (*m)->u.m.e[0];
	free(p);
    }
    if (*m)
	for (i = 0; i < (*m)->u.m.n; i++)
	    if ((*m)->type == S_or || (*m)->type == S_and || (*m)->type == S_exclmark)
		mavis_cond_optimize(&(*m)->u.m.e[i]);
}

struct mavis_cond *mavis_cond_parse(struct sym *sym)
{
    struct sym *cond_sym = NULL;
    if (sym_normalize_cond_start(sym, &cond_sym)) {
	struct mavis_cond *m = mavis_cond_parse_r(cond_sym);
	sym_normalize_cond_end(&cond_sym);
	mavis_cond_optimize(&m);
	return m;
    }
    return mavis_cond_parse_r(sym);
}

#ifdef WITH_PCRE
#define OVECCOUNT 30
static int ovector[OVECCOUNT];
static uint32_t ovector_count = OVECCOUNT;
static int pcre_res = 0;
static char *pcre_arg = NULL;
#endif
#ifdef WITH_PCRE2
static pcre2_match_data *match_data = NULL;
static PCRE2_SIZE *ovector = NULL;
static uint32_t ovector_count = 0;
static int pcre_res = 0;
static PCRE2_SPTR8 pcre_arg = NULL;
#endif

static int mavis_cond_eval_res(mavis_ctx * mcx, struct mavis_cond *m, int res)
{
    char *r = res ? "true" : "false";
    switch (m->type) {
    case S_exclmark:
    case S_and:
    case S_or:
	if (common_data.debug & DEBUG_ACL_FLAG)
	    fprintf(stderr, "%s/line %u: [%s] => %s\n", mcx->identity_source_name, m->line, codestring[m->type], r);
	break;
    default:
	if (common_data.debug & DEBUG_ACL_FLAG)
	    fprintf(stderr, "%s/line %u: [%s] %s%s%s '%s' => %s\n", mcx->identity_source_name, m->line,
		    codestring[m->u.s.token], m->u.s.lhs_txt ? m->u.s.lhs_txt : "",
		    m->u.s.lhs_txt ? " " : "", codestring[m->type], m->u.s.rhs_txt ? m->u.s.rhs_txt : "", r);
    }

    return res;
}

static int mavis_cond_eval(mavis_ctx * mcx, av_ctx * ac, struct mavis_cond *m)
{
    int i, res = 0;
    char *v, *rhs;
    if (!m)
	return 0;
    switch (m->type) {
    case S_exclmark:
	res = !mavis_cond_eval(mcx, ac, m->u.m.e[0]);
	return mavis_cond_eval_res(mcx, m, res);
    case S_and:
	res = -1;
	for (i = 0; res && i < m->u.m.n; i++)
	    res = mavis_cond_eval(mcx, ac, m->u.m.e[i]);
	return mavis_cond_eval_res(mcx, m, res);
    case S_or:
	for (i = 0; !res && i < m->u.m.n; i++)
	    res = mavis_cond_eval(mcx, ac, m->u.m.e[i]);
	return mavis_cond_eval_res(mcx, m, res);
    case S_defined:
	res = av_get(ac, (int) (long) m->u.s.lhs) ? 1 : 0;
	return mavis_cond_eval_res(mcx, m, res);
    case S_undef:
	res = av_get(ac, (int) (long) m->u.s.lhs) ? 0 : 1;
	return mavis_cond_eval_res(mcx, m, res);
    case S_equal:
	if (!(v = av_get(ac, (int) (long) m->u.s.lhs)))
	    return mavis_cond_eval_res(mcx, m, 0);
	rhs = m->u.s.rhs;
	if (rhs && ((int) (long) m->u.s.lhs == AV_A_IDENTITY_SOURCE) && !strcmp(rhs, "self") && !strcmp(v, mcx->identity_source_name))
	    return mavis_cond_eval_res(mcx, m, -1);
	if (!rhs && (m->u.s.token == S_attr))
	    rhs = av_get(ac, (int) (long) m->u.s.rhs);
	if (rhs)
	    return mavis_cond_eval_res(mcx, m, !strcmp(v, rhs));
	return mavis_cond_eval_res(mcx, m, 0);
    case S_regex:
	if (!(v = av_get(ac, (int) (long) m->u.s.lhs)))
	    return mavis_cond_eval_res(mcx, m, 0);
	return !regexec((regex_t *) m->u.s.rhs, v, 0, NULL, 0);
    case S_slash:
#if defined(WITH_PCRE) || defined(WITH_PCRE2)
	if (!(v = av_get(ac, (int) (long) m->u.s.lhs)))
	    return mavis_cond_eval_res(mcx, m, 0);
#ifdef WITH_PCRE
	pcre_res = pcre_exec((pcre *) m->u.s.rhs, NULL, pcre_arg = v, (int) strlen(v), 0, 0, ovector, OVECCOUNT);
#else
#ifdef WITH_PCRE2
	if (match_data) {
	    pcre2_match_data_free(match_data);
	    match_data = NULL;
	}
	match_data = pcre2_match_data_create_from_pattern((pcre2_code *) m->u.s.rhs, NULL);
	pcre_arg = (PCRE2_SPTR8) v;
	pcre_res = pcre2_match((pcre2_code *) m->u.s.rhs, pcre_arg, (PCRE2_SIZE) strlen(v), 0, 0, match_data, NULL);
	if (pcre_res < 0 && pcre_res != PCRE2_ERROR_NOMATCH)
	    report_cfg_error(LOG_INFO, ~0, "PCRE2 matching error: %d", pcre_res);
	ovector = pcre2_get_ovector_pointer(match_data);
	ovector_count = pcre2_get_ovector_count(match_data);
#endif
	res = -1 < pcre_res;
	return mavis_cond_eval_res(mcx, m, res);
#endif
#else
	report_cfg_error(LOG_INFO, ~0, "You're using PCRE syntax, but this binary wasn't compiled with PCRE support.");
#endif
    default:;
    }
    return 0;
}

static void mavis_cond_drop(struct mavis_cond **m)
{
    int i;
    switch ((*m)->type) {
    case S_and:
    case S_or:
    case S_exclmark:
	for (i = 0; i <= (*m)->u.m.n; i++)
	    mavis_cond_drop(&(*m)->u.m.e[i]);
    case S_equal:
	free((*m)->u.s.rhs);
	break;
    case S_regex:
	regfree((*m)->u.s.rhs);
	break;
    case S_slash:
#ifdef WITH_PCRE
	pcre_free((*m)->u.s.rhs);
#endif
#ifdef WITH_PCRE2
	pcre2_code_free((*m)->u.s.rhs);
#endif
	break;
    default:;
    }
    if ((*m)->u.s.lhs_txt)
	free((*m)->u.s.lhs_txt);
    if ((*m)->u.s.rhs_txt)
	free((*m)->u.s.rhs_txt);
    free(*m);
    *m = NULL;
}

void mavis_script_drop(struct mavis_action **m)
{
    if (*m) {

	switch ((*m)->code) {
	case S_if:
	    mavis_script_drop(&(*m)->b.a);
	    mavis_script_drop(&(*m)->c.a);
	    break;
	case S_eval:
	    mavis_cond_drop(&(*m)->a.c);
	    break;
	case S_set:
	    free((*m)->b.v);
	default:;
	}
	if ((*m)->n)
	    mavis_script_drop(&(*m)->n);
	free(*m);
	*m = NULL;
    }
}

static void mavis_script_eval_debug(mavis_ctx * mcx, struct mavis_action *m)
{
    if (common_data.debug & DEBUG_ACL_FLAG)
	fprintf(stderr, "%s/line %u: [%s]\n", mcx->identity_source_name, m->line, codestring[m->code]);
}

static enum token mavis_script_eval_r(mavis_ctx * mcx, av_ctx * ac, struct mavis_action *m)
{
    enum token r;

    if (!m)
	return S_unknown;

    switch (m->code) {
    case S_continue:
    case S_return:
    case S_skip:
	mavis_script_eval_debug(mcx, m);
	return m->code;
    case S_set:
	{
#if defined(WITH_PCRE) || defined(WITH_PCRE2)
	    uint32_t i;
#endif
	    char s[4096];	// yeah, this sucks.
	    char *v = m->b.v;
	    char *se = s + sizeof(s) - strlen(v) - 100;
	    char *t = s;
	    while (*v && t < se) {
		switch (*v) {
		case '$':
		    v++;
		    if (!isdigit((int) *v)) {
			*t++ = '$';
			break;
		    }
#if defined(WITH_PCRE) || defined(WITH_PCRE2)
		    i = *v - '0';
#endif
		    v++;
#if defined(WITH_PCRE) || defined(WITH_PCRE2)
		    if (pcre_arg
#ifdef WITH_PCRE2
			&& ovector
#endif
			&& i < ovector_count && ovector[2 * i] < ovector[2 * i + 1]) {
			size_t l = ovector[2 * i + 1] - ovector[2 * i];
			if (((int) (se - t) > (int) l)) {
			    strncpy(t, (char *) pcre_arg + ovector[2 * i], l);
			    t += l;
			}
		    }
#else
		    report_cfg_error(LOG_INFO, ~0, "You're using PCRE syntax, but this binary wasn't compiled with PCRE support.");
#endif
		    continue;
		case '\\':
		    v++;
		    if (!*v)
			continue;
		default:;
		}
		*t++ = *v++;
	    }
	    *t = 0;
	    av_set(ac, m->a.a, s);
	    if (common_data.debug & DEBUG_ACL_FLAG) {
		size_t len = strlen(s);
		size_t olen = len * 4 + 1;
		char *out = alloca(olen);
		fprintf(stderr, "%s/line %u: [%s] %s = \"%s\"\n", mcx->identity_source_name, m->line, codestring[m->code], av_char[m->a.a].name, escape_string(s, len, out, &olen));
	    }
	}
	break;
    case S_unset:
	av_unset(ac, m->a.a);
	mavis_script_eval_debug(mcx, m);
	if (common_data.debug & DEBUG_ACL_FLAG)
	    fprintf(stderr, "%s/line %u: [%s] %s\n", mcx->identity_source_name, m->line, codestring[m->code], av_char[m->a.a].name);
	break;
    case S_reset:
	if (mcx->ac_bak)
	    av_set(ac, m->a.a, av_get(mcx->ac_bak, m->a.a));
	mavis_script_eval_debug(mcx, m);
	break;
    case S_toupper:{
	    char *t = av_get(ac, m->a.a);
	    if (t)
		for (; *t; t++)
		    *t = toupper((int) *t);
	    mavis_script_eval_debug(mcx, m);
	    break;
	}
    case S_tolower:{
	    char *t = av_get(ac, m->a.a);
	    if (t)
		for (; *t; t++)
		    *t = tolower((int) *t);
	    mavis_script_eval_debug(mcx, m);
	    break;
	}
    case S_eval:
	mavis_cond_eval(mcx, ac, m->a.c);
	break;
    case S_if:
	if (mavis_cond_eval(mcx, ac, m->a.c)) {
	    r = mavis_script_eval_r(mcx, ac, m->b.a);
	    if (r != S_unknown)
		return r;
	} else if (m->c.a) {
	    if (common_data.debug & DEBUG_ACL_FLAG)
		fprintf(stderr, "%s/line %u: [%s]\n", mcx->identity_source_name, m->line, codestring[S_else]);
	    r = mavis_script_eval_r(mcx, ac, m->c.a);
	    if (r != S_unknown)
		return r;
	}
	break;
    default:
	return S_unknown;
    }
    return m->n ? mavis_script_eval_r(mcx, ac, m->n) : S_unknown;
}

struct mavis_action *mavis_action_new(struct sym *sym)
{
    struct mavis_action *m = NULL;
    m = calloc(1, sizeof(struct mavis_action));
    m->code = sym->code;
    m->line = sym->line;
    sym_get(sym);
    return m;
}

static struct mavis_action *mavis_script_parse_r(mavis_ctx * mcx, struct sym *sym, int section)
{
    struct mavis_action *m = NULL;

    switch (sym->code) {
    case S_eof:
	parse_error(sym, "EOF unexpected");
    case S_closebra:
	return NULL;
    case S_openbra:
	sym_get(sym);
	m = mavis_script_parse_r(mcx, sym, 1);
	parse(sym, S_closebra);
	break;
    case S_return:
    case S_continue:
    case S_skip:
	m = mavis_action_new(sym);
	break;
    case S_reset:
	mcx->ac_bak_required = 1;
    case S_set:
    case S_unset:
    case S_toupper:
    case S_tolower:
	m = mavis_action_new(sym);
	m->a.a = av_attr_token_to_i(sym);
	if (m->a.a < 0)
	    parse_error(sym, "'%s' is not a recognized attribute", sym->buf);
	sym_get(sym);
	if (m->code == S_set) {
	    parse(sym, S_equal);
	    m->b.v = strdup(sym->buf);
	    sym_get(sym);
	}
	break;
    case S_eval:
	m = mavis_action_new(sym);
	m->a.c = mavis_cond_parse(sym);
	break;
    case S_if:
	m = mavis_action_new(sym);
	m->a.c = mavis_cond_parse(sym);
#ifdef MAVIS_COND_DUMP
	mavis_cond_dump(m->a.c);
#endif
	m->b.a = mavis_script_parse_r(mcx, sym, 0);
	if (sym->code == S_else) {
	    sym_get(sym);
	    m->c.a = mavis_script_parse_r(mcx, sym, 0);
	}
	break;
    default:
	parse_error_expect(sym, S_if, S_unset, S_set, S_skip, S_reset, S_toupper, S_tolower, S_return, S_continue, S_openbra, S_unknown);
    }
    if (section && sym->code != S_closebra && sym->code != S_eof)
	m->n = mavis_script_parse_r(mcx, sym, section);
    return m;
}

void mavis_script_parse(mavis_ctx * mcx, struct sym *sym)
{
    struct mavis_action **m = NULL;

    sym_get(sym);

    switch (sym->code) {
    case S_in:
	m = &mcx->script_in;
	break;
    case S_out:
	m = &mcx->script_out;
	break;
    case S_interim:
	m = &mcx->script_interim;
	break;
    default:
	parse_error_expect(sym, S_in, S_out, S_openbra, S_unknown);
    }

    while (*m)
	m = &(*m)->n;

    sym_get(sym);

    if (sym->code == S_equal)
	sym_get(sym);
    parse(sym, S_openbra);
    *m = mavis_script_parse_r(mcx, sym, 1);

    parse(sym, S_closebra);
}

enum token mavis_script_eval(mavis_ctx * mcx, av_ctx * ac, struct mavis_action *m)
{
#if defined(WITH_PCRE) || defined(WITH_PCRE2)
    pcre_res = 0;
    pcre_arg = NULL;
#endif
    return mavis_script_eval_r(mcx, ac, m);
}

static int dow2n(char *t)
{
    int i = 0;
    char *d = "sunmontuewedthufrisat";
    while (d[i] && strncasecmp(d + i, t, 3))
	i += 3;
    return i / 3;
}

static int mon2n(char *t)
{
    int i = 0;
    char *d = "janfebmaraprmayjunjulaugsepoctnovdec";
    while (d[i] && strncasecmp(d + i, t, 3))
	i += 3;
    return i / 3;
}

int parse_cron(struct mavis_tm *tm, char *t)
{
    int start = -1, val = 0, field = 0, valid = 0, i;
    long long a[5];
    int amax[5] = { 60, 24, 31, 12, 7 };

    memset(&a, 0, sizeof(a));

    while (*t && field < 5) {
	switch (*t) {
	case '-':
	    start = val;
	    val = 0;
	    t++;
	    break;
	case '*':
	    a[field] = ~0;
	    field++;
	    t++;
	    while (*t && (*t == ' ' || *t == '\t' || *t == '\n'))
		t++;
	    break;
	case ',':
	    if (start < 0)
		start = val;
	    if (valid)
		for (i = start; i <= val; i++)
		    a[field] |= 1LL << i;
	    t++;
	    valid = 0;
	    start = -1;
	    val = 0;
	    break;
	case ' ':
	case '\t':
	case '\r':
	case '\n':
	    if (start < 0)
		start = val;
	    if (valid)
		for (i = start; i <= val; i++)
		    a[field] |= 1LL << i;
	    valid = 0;
	    while (*t && (*t == ' ' || *t == '\t' || *t == '\n'))
		t++;
	    field++;
	    start = -1;
	    val = 0;
	    break;
	default:
	    if (*t >= '0' && *t <= '9') {
		while (*t >= '0' && *t <= '9') {
		    val *= 10;
		    val += *t - '0';
		    t++;
		}
		valid = 1;
		if (field == 4)
		    val %= 7;
		if (val > amax[field])
		    val = amax[field];
	    } else if ((field == 4 && amax[field] >= (val = dow2n(t)))
		       || (field == 3 && amax[field] >= (val = mon2n(t)))) {
		valid = 1, t += 3;
		val = val % amax[field];
		if (start > -1 && val < start) {
		    for (i = start; i < amax[field]; i++)
			a[field] |= 1LL << i;
		    start = 0;
		}
	    } else
		return 1;
	}
    }
    if (start < 0)
	start = val;
    if (valid)
	for (i = start; i <= val; i++)
	    a[field] |= 1LL << i;

    tm->min = a[0];
    tm->hour = (long) (a[1] & 0xFFFFFFFF);
    tm->mday = (long) (a[2] & 0xFFFFFFFF);
    tm->mon = (long) (a[3] & 0xFFFFFFFF);
    tm->wday = (long) (a[4] & 0xFFFFFFFF);

    return 0;
}

static __inline__ int check_cron(struct mavis_tm *tm, struct tm *loc)
{
    return (tm->min & (1LL << loc->tm_min))
	&& (tm->hour & (1L << loc->tm_hour))
	&& (tm->mon & (1L << loc->tm_mon))
	&& (tm->mday & (1L << loc->tm_mday))
	&& (tm->wday & (1L << loc->tm_wday));
}

int eval_timespec(struct mavis_timespec *ts, char **s)
{
    if (ts->valid_until < (time_t) io_now.tv_sec) {
	struct mavis_tm *tm;
	time_t dummy = (time_t) io_now.tv_sec;
	struct tm *loc = localtime(&dummy);

	ts->matched = 0;
	ts->string = NULL;
	for (tm = ts->tm; tm; tm = tm->next)
	    if (check_cron(tm, loc)) {
		ts->matched = ~0;
		ts->string = tm->string;
		break;
	    }
	ts->valid_until = io_now.tv_sec - loc->tm_sec + 60;
    }

    if (s)
	*s = ts->string;

    return ts->matched;
}

//static rb_tree_t *timespectable = NULL;


static int compare_timespec(const void *a, const void *b)
{
    return strcmp(((struct mavis_timespec *) a)->name, ((struct mavis_timespec *) b)->name);
}

rb_tree_t *init_timespec(void)
{
    return RB_tree_new(compare_timespec, NULL);
}

static int parse_uucptime(struct mavis_tm *, char *in);

void parse_timespec(rb_tree_t * timespectable, struct sym *sym)
{
    struct mavis_timespec *ts;
    size_t l;

    sym_get(sym);
    if (sym->code == S_equal)
	sym_get(sym);
    l = strlen(sym->buf);

    ts = alloca(sizeof(struct mavis_timespec) + l);
    strcpy(ts->name, sym->buf);

    ts = RB_lookup(timespectable, (void *) ts);
    if (!ts) {
	ts = (struct mavis_timespec *) calloc(1, sizeof(struct mavis_timespec)
					      + l);
	strcpy(ts->name, sym->buf);
	RB_insert(timespectable, ts);
    }

    sym_get(sym);
    parse(sym, S_openbra);

    while (1)
	switch (sym->code) {
	case S_eof:
	    parse_error(sym, "EOF unexpected");
	case S_closebra:
	    sym_get(sym);
	    return;
	default:{
		struct mavis_tm **tm = &ts->tm;
		while (*tm)
		    tm = &(*tm)->next;
		*tm = calloc(1, sizeof(struct mavis_tm));
		(*tm)->string = strdup(sym->buf);
		if (isalpha((int) sym->buf[0])) {
		    if (parse_uucptime(*tm, sym->buf))
			parse_error(sym, "Unrecognized 'uucp' style time specification '%s'", sym->buf);

		} else {
		    if (parse_cron(*tm, sym->buf))
			parse_error(sym, "Unrecognized 'cron' style time specification '%s'", sym->buf);
		}
		sym_get(sym);
	    }
	}
}

struct mavis_timespec *find_timespec(rb_tree_t * timespectable, char *s)
{
    size_t l = strlen(s);
    struct mavis_timespec *ts = alloca(sizeof(struct mavis_timespec) + l);
    strcpy(ts->name, s);
    ts = RB_lookup(timespectable, (void *) ts);
    return ts;
}

static char *uucpdow2n(char **t)
{
    int i = 0;
    char *d = "sumotuwethfrsawkwd";
    char *dn = "0\0\0\0001\0\0\0002\0\0\0003\0\0\0004\0\0\0" "5\0\0\0006\0\0\0001-5\0000,6";
    while (d[i] && strncasecmp(d + i, *t, 2))
	i += 2;
    if (d[i]) {
	*t += 2;
	return dn + 2 * i;
    }
    if (!strncasecmp("any", *t, 3)) {
	*t += 3;
	return "*";
    }
    return NULL;
}

static void uucptime2cron(struct mavis_tm *tm, int from, int to, char *dow)
{
    char tmp[80];
    if (from / 100 == to / 100) {
	snprintf(tmp, sizeof(tmp), "%d-%d %d * * %s", from % 100, to % 100, from / 100, dow);
	parse_cron(tm, tmp);
	return;
    }
    if (from % 100) {
	snprintf(tmp, sizeof(tmp), "%d-59 %d * * %s", from % 100, from / 100, dow);
	parse_cron(tm, tmp);
	from /= 100;
	from++;
	from *= 100;
    }
    if (to % 100 != 59) {
	snprintf(tmp, sizeof(tmp), "0-%d %d * * %s", to % 100, to / 100, dow);
	parse_cron(tm, tmp);
	to /= 100;
	to--;
	to *= 100;
    }
    if (from == to) {
	snprintf(tmp, sizeof(tmp), "* %d * * %s", from / 100, dow);
	parse_cron(tm, tmp);
    } else if (from < to) {
	snprintf(tmp, sizeof(tmp), "* %d-%d * * %s", from / 100, to / 100, dow);
	parse_cron(tm, tmp);
    }
}

static int parse_uucptime(struct mavis_tm *tm, char *in)
{
    char *uucptime;
    while ((uucptime = strtok(in, ",|"))) {
	in = NULL;
	char *dow = uucpdow2n(&uucptime);
	if (!dow)
	    return -1;
	if (*uucptime) {
	    int i;
	    int from = 0, to = 0;
	    for (i = 0; i < 4; i++) {
		if (!isdigit((int) *uucptime))
		    return -1;
		from *= 10;
		from += *uucptime - '0';
		uucptime++;
	    }
	    if (from / 100 > 23 || from % 100 > 59)
		return -1;
	    if (*uucptime != '-')
		return -1;
	    uucptime++;
	    to = 0L;
	    for (i = 0; i < 4; i++) {
		if (!isdigit((int) *uucptime))
		    return -1;
		to *= 10;
		to += *uucptime - '0';
		uucptime++;
	    }
	    if (from < to) {
		uucptime2cron(tm, from, to, dow);
	    } else {
		uucptime2cron(tm, from, 2359, dow);
		uucptime2cron(tm, 0, to, dow);
	    }
	    if (to / 100 > 23 || to % 100 > 59)
		return -1;
	    if (*uucptime)
		return -1;
	} else {
	    char tmp[80];
	    snprintf(tmp, sizeof(tmp), "* * * * %s", dow);
	    parse_cron(tm, tmp);
	}
    }
    return 0;

}

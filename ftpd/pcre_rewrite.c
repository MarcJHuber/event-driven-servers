/*
 * pcre_rewrite.c
 * (C)1999-2011 Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

/*
 * This code was tested with version 2.08 of the PCRE library,
 * available from:
 * ftp://ftp.cus.cam.ac.uk/pub/software/programs/pcre/
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef WITH_PCRE
#include <pcre.h>
#endif
#ifdef WITH_PCRE2
#include <pcre2.h>
#endif
#include "headers.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

#ifdef WITH_PCRE
struct pcre_rule {
    pcre *p;
    pcre_extra *pe;
    struct pcre_rule *next;
    char *flags;
    char replacement[1];
};
#endif
#ifdef WITH_PCRE2
struct pcre_rule {
    pcre2_code *p;
    PCRE2_SIZE rlength;		/* strlen(replacement string) */
    struct pcre_rule *next;
    char *flags;
    char replacement[1];
};
#endif

static struct pcre_rule *pcre_start = NULL, *pcre_last = NULL;

int PCRE_add(char *regex, char *replacement, char *flags)
{
    struct pcre_rule *pr;
#ifdef WITH_PCRE
    const char *errptr;
    int erroffset;
#endif
#ifdef WITH_PCRE2
    int errorcode;
    PCRE2_SIZE erroffset;
#endif

    if (!flags || !*flags)
	flags = "L";

    pr = Xcalloc(1, sizeof(struct pcre_rule)
		 + strlen(replacement) + strlen(flags) + 1);

#ifdef WITH_PCRE
    pr->p = pcre_compile(regex, 0, &errptr, &erroffset, NULL);
    if (!pr->p) {
	logmsg("pcre_compile: %s: %s", regex, errptr ? errptr : "(NULL)");
	free(pr);
	return -1;
    }

    pr->pe = pcre_study(pr->p, 0, &errptr);
#endif
#ifdef WITH_PCRE2
    pr->p = pcre2_compile((PCRE2_SPTR) regex, PCRE2_ZERO_TERMINATED, PCRE2_UTF, &errorcode, &erroffset, NULL);
    if (!pr->p) {
	PCRE2_UCHAR buffer[256];
	pcre2_get_error_message(errorcode, buffer, sizeof(buffer));
	logmsg("pcre2_compile: %s: %s", regex, buffer);
	free(pr);
	return -1;
    }
#endif

    strcpy(pr->replacement, replacement);
    pr->flags = pr->replacement + strlen(pr->replacement) + 2;
    strcpy(pr->flags, flags);
    pr->next = NULL;

    if (!pcre_start)
	pcre_start = pcre_last = pr;
    else {
	pcre_last->next = pr;
	pcre_last = pr;
    }

    Debug((DEBUG_PROC, " PCRE_add(%s, %s, %s)\n", regex, replacement, flags));
    return 0;
}

int PCRE_exec(const char *inbuf, char *outbuf, size_t outlen)
{
    int loopmax = 20;
#ifdef WITH_PCRE
#define OVECSIZE 100
    int ovector[3 * (OVECSIZE + 1)];
#endif
    struct pcre_rule *pr = pcre_start;
    size_t tbuflen = 2 * outlen;
    char *tbuf = alloca(tbuflen);

    if (!pcre_start)
	return 0;		/* no match */

    strncpy(tbuf, inbuf, tbuflen);
    tbuf[tbuflen - 1] = 0;

    while (loopmax--) {
	int m;
#ifdef WITH_PCRE2
	pcre2_match_data *match_data = NULL;
	PCRE2_SIZE outlength = (PCRE2_SIZE) outlen - 1;
#endif
	if (pr == NULL)
	    pr = pcre_start;
#ifdef WITH_PCRE
	m = pcre_exec(pr->p, pr->pe, tbuf, (int) strlen(tbuf), 0, 0, ovector, OVECSIZE);
	if (m > -1) {
	    char *o, *t;

	    for (o = outbuf, t = pr->replacement; *t && o < outbuf + tbuflen; t++)
		switch (*t) {
		case '\\':	/* escape next character */
		    if (*(t + 1))
			*o++ = *t++;
		    break;
		case '$':
		    if (*(t + 1)) {
			int num = 0;

			if (isdigit((int) *++t))
			    num = *t - '0';
			else if (*t == '{')
			    for (t++; *t && *t != '}'; t++) {
				if (isdigit((int) *t))
				    num = num * 10 + *t - '0';
			} else
			    continue;

			pcre_copy_substring(tbuf, ovector, m, num, o, (int) (outbuf + outlen - o - 1));
			while (*o)
			    o++;
		    }
		    break;
		default:
		    *o++ = *t;
		}		/* switch */

	    *o = 0;
	    if (!strcmp(pr->flags, "N")) {	/* Next */
		pr = pcre_start;
		strncpy(tbuf, outbuf, tbuflen);
		tbuf[tbuflen - 1] = 0;
		continue;
	    }
	    if (!strcmp(pr->flags, "R"))	/* Reject */
		*outbuf = 0;
	    Debug((DEBUG_PROC, " PCRE_exec(%s) = %s\n", inbuf, outbuf));
	    return -1;
	}
#endif
#ifdef WITH_PCRE2
	// caveat emptor: compiles, but untested
	match_data = pcre2_match_data_create_from_pattern(pr->p, NULL);
	m = pcre2_substitute(pr->p, (PCRE2_SPTR) tbuf, PCRE2_ZERO_TERMINATED, PCRE2_SUBSTITUTE_EXTENDED | PCRE2_UTF, 0, match_data,
			     NULL, (PCRE2_SPTR) pr->replacement, PCRE2_ZERO_TERMINATED, (PCRE2_UCHAR8 *) outbuf, &outlength);

	if (match_data) {
	    pcre2_match_data_free(match_data);
	    match_data = NULL;
	}

	if (m > -1) {
	    if (outlength > 1 && outlength < (PCRE2_SIZE) outlen)
		outbuf[outlen] = 0;

	    if (!strcmp(pr->flags, "N")) {	/* Next */
		pr = pcre_start;
		strncpy(tbuf, outbuf, tbuflen);
		tbuf[tbuflen - 1] = 0;
		continue;
	    }
	    if (!strcmp(pr->flags, "R"))	/* Reject */
		*outbuf = 0;
	    Debug((DEBUG_PROC, " PCRE_exec(%s) = %s\n", inbuf, outbuf));
	    return -1;
	}
#endif				/* if */
	pr = pr->next;
    }				/* while */
    return 0;
}

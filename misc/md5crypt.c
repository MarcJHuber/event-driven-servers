/*	$Id$	*/

/*	$OpenBSD: md5crypt.c,v 1.14 2005/08/08 08:05:33 espie Exp $	*/

/*
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <phk@login.dknet.dk> wrote this file.  As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.   Poul-Henning Kamp
 * ----------------------------------------------------------------------------
 *
 * $FreeBSD: crypt.c,v 1.5 1996/10/14 08:34:02 phk Exp $
 *
 */

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include "misc/mymd5.h"
#include <string.h>

static const char rcsid[] __attribute__((used)) = "$Id$";

static unsigned char itoa64[] =	/* 0 ... 63 => ascii - 64 */
    "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

static void to64(char *, u_int, int);

static void to64(char *s, u_int v, int n)
{
    while (--n >= 0) {
	*s++ = itoa64[v & 0x3f];
	v >>= 6;
    }
}

/*
 * UNIX password
 *
 * Use MD5 for what it is best at...
 */

char *md5crypt(const char *pw, const char *salt);

char *md5crypt(const char *pw, const char *salt)
{
    /*
     * This string is magic for this algorithm.  Having
     * it this way, we can get get better later on
     */
    static unsigned char *magic = (unsigned char *) "$1$";

    static char passwd[120], *p;
    static const unsigned char *sp, *ep;
    unsigned char final[16];
    int sl, pl, i;
    myMD5_CTX ctx, ctx1;
    u_int l;
    size_t pw_len = strlen(pw);

    /* Refine the Salt first */
    sp = (const unsigned char *) salt;

    /* If it starts with the magic string, then skip that */
    if (!strncmp((const char *) sp, (const char *) magic, strlen((const char *) magic)))
	sp += strlen((const char *) magic);

    /* It stops at the first '$', max 8 chars */
    for (ep = sp; *ep && *ep != '$' && ep < (sp + 8); ep++)
	continue;

    /* get the length of the true salt */
    sl = ep - sp;

    myMD5Init(&ctx);

    /* The password first, since that is what is most unknown */
    myMD5Update(&ctx, (void *) pw, pw_len);

    /* Then our magic string */
    myMD5Update(&ctx, magic, strlen((const char *) magic));

    /* Then the raw salt */
    myMD5Update(&ctx, (void *) sp, sl);

    /* Then just as many characters of the MD5(pw,salt,pw) */
    myMD5Init(&ctx1);
    myMD5Update(&ctx1, (void *) pw, pw_len);
    myMD5Update(&ctx1, (void *) sp, sl);
    myMD5Update(&ctx1, (void *) pw, pw_len);
    myMD5Final(final, &ctx1);
    for (pl = pw_len; pl > 0; pl -= 16)
	myMD5Update(&ctx, final, pl > 16 ? 16 : pl);

    /* Don't leave anything around in vm they could use. */
    memset(final, 0, sizeof final);

    /* Then something really weird... */
    for (i = pw_len; i; i >>= 1)
	if (i & 1)
	    myMD5Update(&ctx, final, 1);
	else
	    myMD5Update(&ctx, (void *) pw, 1);

    /* Now make the output string */
    snprintf(passwd, sizeof(passwd), "%s%.*s$", (char *) magic, sl, (const char *) sp);

    myMD5Final(final, &ctx);

    /*
     * and now, just to make sure things don't run too fast
     * On a 60 Mhz Pentium this takes 34 msec, so you would
     * need 30 seconds to build a 1000 entry dictionary...
     */
    for (i = 0; i < 1000; i++) {
	myMD5Init(&ctx1);
	if (i & 1)
	    myMD5Update(&ctx1, (void *) pw, pw_len);
	else
	    myMD5Update(&ctx1, final, 16);

	if (i % 3)
	    myMD5Update(&ctx1, (void *) sp, sl);

	if (i % 7)
	    myMD5Update(&ctx1, (void *) pw, pw_len);

	if (i & 1)
	    myMD5Update(&ctx1, final, 16);
	else
	    myMD5Update(&ctx1, (void *) pw, pw_len);
	myMD5Final(final, &ctx1);
    }

    p = passwd + strlen(passwd);

    l = (final[0] << 16) | (final[6] << 8) | final[12];
    to64(p, l, 4);
    p += 4;
    l = (final[1] << 16) | (final[7] << 8) | final[13];
    to64(p, l, 4);
    p += 4;
    l = (final[2] << 16) | (final[8] << 8) | final[14];
    to64(p, l, 4);
    p += 4;
    l = (final[3] << 16) | (final[9] << 8) | final[15];
    to64(p, l, 4);
    p += 4;
    l = (final[4] << 16) | (final[10] << 8) | final[5];
    to64(p, l, 4);
    p += 4;
    l = final[11];
    to64(p, l, 2);
    p += 2;
    *p = '\0';

    /* Don't leave anything around in vm they could use. */
    memset(final, 0, sizeof final);

    return passwd;
}

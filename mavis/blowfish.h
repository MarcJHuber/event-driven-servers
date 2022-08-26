/*
 * blowfish.h
 * (c)1999,2000 Marc Huber <Marc.Huber@web.de>
 *
 * $Id: blowfish.h,v 1.3 2005/10/01 11:26:24 huber Exp marc $
 *
 */

#ifndef __BLOWFISH_H__
#define __BLOWFISH_H__
#include <sys/types.h>

typedef union {
    char s[1];
    u_int n[1];
} a_char;			/* aligned char */

struct blowfish_ctx;

struct blowfish_ctx *blowfish_init(char *, size_t);
size_t blowfish_enc(struct blowfish_ctx *, a_char *, size_t);
size_t blowfish_dec(struct blowfish_ctx *, a_char *, size_t);

#endif				/* __BLOWFISH_H__ */

#if !defined( __MY_MD5_H_)
#define __MY_MD5_H_

/*
 * MD5.H - header file for MD5C.C
 */

/* Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
 * rights reserved.
 *
 * License to copy and use this software is granted provided that it
 * is identified as the "RSA Data Security, Inc. MD5 Message-Digest
 * Algorithm" in all material mentioning or referencing this software
 * or this function.
 *
 * License is also granted to make and use derivative works provided
 * that such works are identified as "derived from the RSA Data
 * Security, Inc. MD5 Message-Digest Algorithm" in all material
 * mentioning or referencing the derived work.
 *
 * RSA Data Security, Inc. makes no representations concerning either
 * the merchantability of this software or the suitability of this
 * software for any particular purpose. It is provided "as is"
 * without express or implied warranty of any kind.
 *
 * These notices must be retained in any copies of any part of this
 * documentation and/or software.
 */

/*
 * $Id: mymd5.h,v 1.5 2008/05/22 18:45:37 marc Exp $
 *
 */

#include <sys/types.h>
#include <sys/uio.h>

/* MD5 context. */
typedef struct {
    u_int state[4];		/* state (ABCD) */
    u_int count[2];		/* number of bits, modulo 2^64 (lsb first) */
    u_char buffer[64];		/* input buffer */
} myMD5_CTX;

void myMD5Init(myMD5_CTX *);
void myMD5Update(myMD5_CTX *, void *, size_t);
void myMD5Final(u_char[16], myMD5_CTX *);

int md5v(u_char *digest, size_t digest_len, const struct iovec *iov, int iovcnt);
#endif

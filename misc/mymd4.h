#ifndef _MD4_H_
#define _MD4_H_
/* MD4.H - header file for MD4C.C
 */

/* Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
   rights reserved.

   License to copy and use this software is granted provided that it
   is identified as the "RSA Data Security, Inc. MD4 Message-Digest
   Algorithm" in all material mentioning or referencing this software
   or this function.

   License is also granted to make and use derivative works provided
   that such works are identified as "derived from the RSA Data
   Security, Inc. MD4 Message-Digest Algorithm" in all material
   mentioning or referencing the derived work.

   RSA Data Security, Inc. makes no representations concerning either
   the merchantability of this software or the suitability of this
   software for any particular purpose. It is provided "as is"
   without express or implied warranty of any kind.

   These notices must be retained in any copies of any part of this
   documentation and/or software.
 */

 /* $Id: mymd4.h,v 1.2 2005/12/31 12:14:23 huber Exp $ */

/* MD4 context. */
typedef struct {
    u_int state[4];		/* state (ABCD) */
    u_int count[2];		/* number of bits, modulo 2^64 (lsb first) */
    u_char buffer[64];		/* input buffer */
} myMD4_CTX;

void MD4Init(myMD4_CTX *);
void MD4Update(myMD4_CTX *, u_char *, u_int);
void MD4Final(u_char[16], myMD4_CTX *);
#endif

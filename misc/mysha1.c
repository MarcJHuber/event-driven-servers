/*
 * mysha1.c
  * (C)2026 by Marc Huber <Marc.Huber@web.de>
  *
 * $Id$
 */

#include "misc/sysconf.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

#include "misc/mysha1.h"
#if OPENSSL_VERSION_NUMBER < 0x30000000
#include <openssl/sha.h>
#else
#include <openssl/types.h>
#include <openssl/evp.h>
#endif

int sha1v(u_char *digest, size_t digest_len, const struct iovec *iov, int iovcnt)
{
    if (!digest || digest_len != SHA_DIGEST_LENGTH)
	return -1;

#if OPENSSL_VERSION_NUMBER < 0x30000000
    SHA_CTX ctx;
    SHA1_Init(&ctx);
    for (int i = 0; i < iovcnt; i++)
	SHA1_Update(&ctx, iov[i].iov_base, iov[i].iov_len);
    SHA1_Final(digest, &ctx);
#else
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha1(), NULL);
	for (int i = 0; i < iovcnt; i++)
	    EVP_DigestUpdate(ctx, iov[i].iov_base, iov[i].iov_len);
    u_int dummy;
    EVP_DigestFinal_ex(ctx, digest, &dummy);
    EVP_MD_CTX_free(ctx);
#endif
    return 0;
}

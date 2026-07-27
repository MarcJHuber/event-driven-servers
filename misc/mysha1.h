#if !defined( __MY_SHA1_H_)
#define __MY_SHA1_H_

#include <sys/types.h>
#include <sys/uio.h>

int sha1v(u_char *digest, size_t digest_len, const struct iovec *iov, int iovcnt);
#endif

/*
 * mysendfile.c
 * 
 * (C)2001-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 */


#include "misc/sysconf.h"
#include "misc/mysendfile.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

#ifdef WITH_SENDFILE

#if defined(__linux__)

#if defined(_LP64)
#include <sys/sendfile.h>
ssize_t mysendfile(int out_fd, int in_fd, off_t * offset, size_t count)
{
    return sendfile(out_fd, in_fd, offset, count);
}


#else				/* _LP64 */
#include <features.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <asm/unistd.h>
#include <unistd.h>

/* Special case for 32bit Linux. We've to ensure that there's an automatic
 * fall-back to sendfile if sendfile64 isn't available.
 */

ssize_t mysendfile(int out_fd, int in_fd, off_t * offset, size_t count)
{
    ssize_t res = -1;

#if defined(__USE_FILE_OFFSET64) && defined(__NR_sendfile64)
    static int has_sendfile64 = 1;
    if (has_sendfile64) {
	res = syscall(__NR_sendfile64, out_fd, in_fd, offset, count);
	if (res > -1 || errno != ENOSYS)
	    return res;
	has_sendfile64 = 0;
    }
#endif

#if defined(__USE_FILE_OFFSET64)
    if (*offset + count > 2147483647)
#else
    if (*offset + count < *offset)
#endif
	errno = EOVERFLOW;
    else {
	long int offset32 = (long int) (*offset);
	res = syscall(__NR_sendfile, out_fd, in_fd, &offset32, count);
	*offset = (off_t) offset32;
    }
    return res;
}
#endif				/* _LP64 */
#endif				/* linux */

#if defined(__FreeBSD__) || defined(__DragonFly__)
/*
 * The FreeBSD implementation differs from the Linux/Solaris one.
 * Well, strictly spoken it's the other way around -- FreeBSD was
 * first. Anyway, the Sun guys have adopted the Linux interface,
 * so we're going with that and use a wrapper. Trivial enough.
 */
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/uio.h>

ssize_t mysendfile(int out_fd, int in_fd, off_t * offset, size_t count)
{
    off_t sbytes;
    int result = sendfile(in_fd, out_fd, *offset, count, NULL, &sbytes, 0);
    if (result > -1)
	*offset += sbytes, result = sbytes;
    else if (errno == EAGAIN)
	*offset += sbytes, result = sbytes, errno = 0;
    return result;
}
#endif				/* FreeBSD */

#if defined(__APPLE__)
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/uio.h>

ssize_t mysendfile(int out_fd, int in_fd, off_t * offset, size_t count)
{
    off_t sbytes = count;
    int result = sendfile(in_fd, out_fd, *offset, &sbytes, NULL, 0);
    if (result > -1)
	*offset += sbytes, result = (ssize_t) sbytes;
    else if (errno == EAGAIN)
	*offset += sbytes, result = (ssize_t) sbytes, errno = 0;
    return result;
}
#endif				/* Apple */

#ifdef __sun__
/*
 * sendfilev(3EXT) is available since Solaris 8 7/01
 * sendfile(3EXT) is available since Solaris 9
 *
 * For older Solaris 8 versions, install the current patch cluster, plus
 * either 111297 (Sparc) or 111298 (Intel).
 *
 */

#include <sys/sendfile.h>
#if OSLEVEL < 0x05090000
/*
 * This is Solaris 8. Weird enough, there's a man page for sendfile(3EXT)
 * available in 108809-30, but the function call is unavailable in headers
 * and libraries.
 *
 * We're using sendfilev(3EXT) to emulate sendfile(3EXT) behaviour.
 *
 */
ssize_t mysendfile(int out_fd, int in_fd, off_t * offset, size_t count)
{
    size_t xfer = 0;
    struct sendfilevec vec;
    ssize_t result;

    vec.sfv_fd = in_fd;
    vec.sfv_flag = 0;
    vec.sfv_off = *offset;
    vec.sfv_len = count;

    result = sendfilev(out_fd, &vec, 1, &xfer);
    if (result < 0 && !xfer)
	return result;

    *offset += xfer;

    return xfer;
}
#else
ssize_t mysendfile(int out_fd, int in_fd, off_t * offset, size_t count)
{
    return sendfile(out_fd, in_fd, offset, count);
}
#endif
#endif				/* sun */

#endif				/* WITH_SENDFILE */

/*
 * io.h
 * (C)1998-2011 by Marc Huber <Marc.Huber@web.de>
 *
 * $Id: io.h,v 1.8 2011/07/17 19:12:19 marc Exp $
 *
 */

#ifndef __IO_H__
#define __IO_H__

#include "misc/sysconf.h"
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

static __inline__ ssize_t Read(int fd, void *buf, size_t count)
{
    ssize_t i;

    do
	i = read(fd, buf, count);
    while (i == -1 && errno == EINTR);

    return i;
}

static __inline__ ssize_t Write(int fd, void *buf, size_t count)
{
    ssize_t i;

    do
	i = write(fd, buf, count);
    while (i == -1 && errno == EINTR);

    return i;
}

static __inline__ ssize_t Sendto(int s, void *msg, size_t len, int flags, struct sockaddr *to, socklen_t tolen)
{
    ssize_t i;

    do
	i = sendto(s, msg, len, flags, to, tolen);
    while (i == -1 && errno == EINTR);

    return i;
}

static __inline__ ssize_t Recvfrom(int s, void *buf, size_t len, int flags, struct sockaddr *from, socklen_t * fromlen)
{
    ssize_t i;

    do
	i = recvfrom(s, buf, len, flags, from, fromlen);
    while (i == -1 && errno == EINTR);

    return i;
}

#endif				/* __IO_H__ */

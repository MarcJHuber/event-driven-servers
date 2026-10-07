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
#include <sys/uio.h>

static __inline__ ssize_t Read(int fd, void *buf, size_t count)
{
    ssize_t i;

    do
	i = read(fd, buf, count);
    while (i == -1 && errno == EINTR);

    return i;
}

static __inline__ ssize_t Write(int fd, const void *buf, size_t count)
{
    ssize_t i;

    do
	i = write(fd, buf, count);
    while (i == -1 && errno == EINTR);

    return i;
}

static __inline__ ssize_t Sendto(int s, const void *msg, size_t len, int flags, struct sockaddr *to, socklen_t tolen)
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

static __inline__ int Connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    int i;

    do
	i = connect(sockfd, addr, addrlen);
    while (i == -1 && errno == EINTR);

    return i;
}

static __inline__ ssize_t Readv(int fd, const struct iovec *iov, int iovcnt)
{
    ssize_t i;

    do
	i = readv(fd, iov, iovcnt);
    while (i == -1 && errno == EINTR);

    return i;
}

static __inline__ ssize_t Writev(int fd, const struct iovec *iov, int iovcnt)
{
    ssize_t i;

    do
	i = writev(fd, iov, iovcnt);
    while (i == -1 && errno == EINTR);

    return i;
}

static __inline__ ssize_t Recv(int sockfd, void *buf, size_t len, int flags)
{
    ssize_t i;

    do
	i = recv(sockfd, buf, len, flags);
    while (i == -1 && errno == EINTR);

    return i;
}

static __inline__ ssize_t Recvmsg(int sockfd, struct msghdr *msg, int flags)
{
    ssize_t i;

    do
	i = recvmsg(sockfd, msg, flags);
    while (i == -1 && errno == EINTR);

    return i;
}

static __inline__ ssize_t Send(int sockfd, const void *buf, size_t len, int flags)
{
    ssize_t i;

    do
	i = send(sockfd, buf, len, flags);
    while (i == -1 && errno == EINTR);

    return i;
}

#endif				/* __IO_H__ */

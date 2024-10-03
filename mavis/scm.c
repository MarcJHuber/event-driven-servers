/*
 * scm.c
 *
 * UNIX domain socket interface for spawnd compliant applications
 * (C)2000-2011 Marc Huber <Marc.Huber@web.de>
 *
 * $Id$
 *
 */

#define __SCM_C__
#include "misc/sysconf.h"
#include "misc/memops.h"
#include "log.h"
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>

#include "mavis/mavis.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

int scm_send_msg(int sock, struct scm_data *sd, int fd)
{
    struct iovec vector;
    struct msghdr msg;
    struct cmsghdr *cmsg;
    char buf[CMSG_SPACE(sizeof(int))] __attribute__((aligned(8)));
    int res;

    vector.iov_base = sd;
    switch (sd->type) {
    case SCM_MAX:
	vector.iov_len = sizeof(struct scm_data_max);
	break;
    case SCM_ACCEPT:
	vector.iov_len = sizeof(struct scm_data_accept);
	break;
    default:
	vector.iov_len = sizeof(struct scm_data);
    }

    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = &vector;
    msg.msg_iovlen = 1;
    msg.msg_flags = 0;

    if (fd > -1) {
	msg.msg_control = (caddr_t) buf;
	msg.msg_controllen = sizeof(buf);
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));
	msg.msg_controllen = cmsg->cmsg_len;
    } else {
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
    }

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif				/* MSG_NOSIGNAL */

    res = sendmsg(sock, &msg, MSG_NOSIGNAL);
    if (res < 0)
	logmsg("scm_send_msg: sendmsg: %s", strerror(errno));
    return (res != (ssize_t) vector.iov_len);
}

int scm_recv_msg(int sock, struct scm_data_accept *sd, size_t sd_len, int *fd)
{
    struct iovec vector;
    struct msghdr msg;
    struct cmsghdr *cmsg;
    char buf[CMSG_SPACE(sizeof(int))] __attribute__((aligned(8)));
    int res;

    if (fd)
	*fd = -1;

    vector.iov_base = sd;
    vector.iov_len = sd_len;
    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = &vector;
    msg.msg_iovlen = 1;
    msg.msg_controllen = CMSG_SPACE(sizeof(int));
    cmsg = (struct cmsghdr *) buf;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    msg.msg_control = (caddr_t) cmsg;

    res = recvmsg(sock, &msg, 0);
    if (0 < res) {
	if (sd->type == SCM_ACCEPT) {
	    struct cmsghdr *chdr = CMSG_FIRSTHDR(&msg);
	    memcpy(fd, CMSG_DATA(chdr), sizeof(int));
	}
	return 0;
    }
    if (res < 0)
	logmsg("scm_recv_msg: recvmsg: %s", strerror(errno));
    return -1;
}

int fakescm_send_msg(int sock __attribute__((unused)), struct scm_data *sd, int fd)
{
    switch (sd->type) {
    case SCM_ACCEPT:
	common_data.scm_accept(fd, (struct scm_data_accept *) sd);
	break;
    case SCM_MAX:
	common_data.users_max = common_data.users_max_total = ((struct scm_data_max *) sd)->max;
	break;
    default:
	;
    }
    return 0;
}

int fakescm_recv_msg(int sock
		     __attribute__((unused)), struct scm_data_accept *sd
		     __attribute__((unused)), size_t sd_len __attribute__((unused)), int *fd __attribute__((unused)))
{
    return 0;
}

void scm_fatal(void)
{
    struct scm_data sd = {.type = SCM_BAD_CFG };
    common_data.scm_send_msg(0, &sd, -1);
    exit(EX_CONFIG);

}

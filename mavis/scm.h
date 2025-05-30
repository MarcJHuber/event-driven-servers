/*
 * smc.h
 *
 * (C)2000-2011 Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id: scm.h,v 1.2 2011/08/21 13:04:50 marc Exp marc $
 *
 */

#ifndef __SCM_H__
#define __SCM_H__

enum scm_token { SCM_DONE = 0, SCM_KEEPALIVE, SCM_MAY_DIE, SCM_DYING, SCM_BAD_CFG, SCM_MAX,
    SCM_ACCEPT, SCM_UDPDATA,
};

struct scm_data {
    enum scm_token type;
    int count;
};

struct scm_data_accept {
    enum scm_token type;
    u_int tls_versions;
    int aaa_protocol;
#define SCM_FLAG_HAPROXY 1
#define SCM_FLAG_RADACCT 2
    u_int flags;
    int socktype;		// SOCK_STREAM, SOCK_SEQPACKET; SOCK_DGRAM
    int protocol;		// AF_INET, AF_INET6, ...
#define SCM_REALM_SIZE 16
    char realm[SCM_REALM_SIZE];
};

struct scm_data_udp {
    enum scm_token type;
    u_int tls_versions;
    int aaa_protocol;
    u_int flags;		// 1: haproxy, 2: radius-accounting
    char realm[SCM_REALM_SIZE];
    short data_len;
    u_char data[] __attribute__((aligned(8)));
};

int scm_send_msg(int, struct scm_data *, int);
int scm_recv_msg(int, struct scm_data_accept *, size_t, int *);
int fakescm_send_msg(int, struct scm_data *, int);
int fakescm_recv_msg(int, struct scm_data_accept *, size_t, int *);
void scm_main(int, char **, char **);
void scm_fatal(void);

#endif				/* __SCM_H__ */

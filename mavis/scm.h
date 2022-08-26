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
    SCM_ACCEPT
};

struct scm_data {
    enum scm_token type;
};

struct scm_data_max {
    enum scm_token type;
    int max;
};

struct scm_data_accept {
    enum scm_token type;
    int socktype;
    int protocol;
    u_int use_tls:1;
    u_int haproxy:1;
#define SCM_REALM_SIZE 16
    char realm[SCM_REALM_SIZE];
};

int scm_send_msg(int, struct scm_data *, int);
int scm_recv_msg(int, struct scm_data_accept *, size_t, int *);
int fakescm_send_msg(int, struct scm_data *, int);
int fakescm_recv_msg(int, struct scm_data_accept *, size_t, int *);
void scm_main(int, char **, char **);
void scm_fatal(void);

#endif				/* __SCM_H__ */

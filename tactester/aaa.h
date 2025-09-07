/*
 * aaa.h
 *
 * RADIUS and TACACS+ client routines
 *
 * (C)2025 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#ifndef __AAACLIENT_AAA_H__
#define __AAACLIENT_AAA_H__

#include "conn.h"

struct aaa {
    struct conn *conn;
#define AAA_ATTR_MAX 64
    int ic;
    struct iovec iv[AAA_ATTR_MAX];
    int oc;
    struct iovec ov[AAA_ATTR_MAX];
    int tac_authen_pap;
    int tac_authen_svc;
    int tac_authen_meth;
};

struct aaa *aaa_new(struct conn *);
void aaa_free(struct aaa *);
void aaa_clear(struct aaa *);

int aaa_authc(struct aaa *, char *user, char *remoteaddr, char *remotetty, char *pass);
int aaa_authz(struct aaa *, char *user, char *remoteaddr, char *remotetty);
int aaa_acct(struct aaa *, char *user, char *remoteaddr, char *remotetty);

void aaa_set_tac_authen_pap(struct aaa *aaa, int onoff);
void aaa_set_tac_authen_svc(struct aaa *aaa, int svc);
void aaa_set_tac_authen_meth(struct aaa *aaa, int meth);

int aaa_set(struct aaa *, u_char * data, size_t data_len);	// "service=shell", "cmd*", encoded radius ...

int aaa_get(struct aaa *, u_char * prefix, size_t prefix_len, int *start, u_char ** data, size_t *data_len);	// returns 0 on success
// *start, if given, is initial 0, and then <matched index +1>

#endif

/*
 * aaa.c
 *
 * RADIUS and TACACS+ client routines
 *
 * (C)2025 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>
#include <arpa/inet.h>
#include "misc/mymd5.h"
#include "tac_plus-ng/protocol_tacacs.h"
#include "tac_plus-ng/protocol_radius.h"
#include "tac_plus-ng/config_radius.h"
#include "aaa.h"

struct aaa *aaa_new(struct conn *conn)
{
    struct aaa *aaa = calloc(1, sizeof(struct aaa));
    aaa->conn = conn;
    aaa->tac_authen_svc = TAC_PLUS_AUTHEN_SVC_LOGIN;
    aaa->tac_authen_meth = TAC_PLUS_AUTHEN_METH_TACACSPLUS;

    return aaa;
}

void aaa_free(struct aaa *aaa)
{
    free(aaa);
}

void aaa_clear(struct aaa *aaa)
{
    for (int i = 0; i < aaa->oc; i++)
	if (aaa->ov[i].iov_base) {
	    free(aaa->ov[i].iov_base);
	    aaa->ov[i].iov_base = NULL;
	    aaa->ov[i].iov_len = 0;
	}
    for (int i = 0; i < aaa->ic; i++)
	if (aaa->iv[i].iov_base) {
	    free(aaa->iv[i].iov_base);
	    aaa->iv[i].iov_base = NULL;
	    aaa->iv[i].iov_len = 0;
	}
    aaa->oc = 0;
    aaa->ic = 0;
}

static __inline__ int minimum(int a, int b)
{
    return (a < b) ? a : b;
}

#define MD5_LEN 16
static void md5_xor(tac_pak_hdr *hdr, char *key, int keylen)
{
    if (key && *key) {
	u_char *data = tac_payload(hdr, u_char *);
	int data_len = ntohl(hdr->datalength), h = 0;
	u_char hash[MD5_LEN][2];

	for (int i = 0; i < data_len; i += 16) {
	    int min = minimum(data_len - i, 16);
	    struct iovec iov[5] = {
		{.iov_base = &hdr->session_id,.iov_len = sizeof(hdr->session_id) },
		{.iov_base = key,.iov_len = keylen },
		{.iov_base = &hdr->version,.iov_len = sizeof(hdr->version) },
		{.iov_base = &hdr->seq_no,.iov_len = sizeof(hdr->seq_no) },
		{.iov_base = hash[h ^ 1],.iov_len = MD5_LEN }
	    };
	    md5v(hash[h], MD5_LEN, iov, i ? 5 : 4);

	    for (int j = 0; j < min; j++)
		data[i + j] ^= hash[h][j];
	    h ^= 1;
	}
	hdr->flags ^= TAC_PLUS_UNENCRYPTED_FLAG;
    }
}

static int authen_reply_looks_bogus(tac_pak_hdr *hdr)
{
    if (hdr->seq_no & 1)
	return -1;
    struct authen_reply *pak = tac_payload(hdr, struct authen_reply *);
    u_int len = TAC_AUTHEN_REPLY_FIXED_FIELDS_SIZE + ntohs(pak->msg_len) + ntohs(pak->data_len);
    u_int datalength = ntohl(hdr->datalength);
    return (len != datalength);
}

static int author_reply_looks_bogus(tac_pak_hdr *hdr)
{
    if (hdr->seq_no & 1)
	return -1;
    struct author_reply *pak = tac_payload(hdr, struct author_reply *);
    u_char *p = (u_char *) pak + TAC_AUTHOR_REPLY_FIXED_FIELDS_SIZE;
    u_int len = TAC_AUTHOR_REPLY_FIXED_FIELDS_SIZE + ntohs(pak->msg_len) + ntohs(pak->data_len);
    u_int datalength = ntohl(hdr->datalength);

    int i;
    for (i = 0; i < (int) pak->arg_cnt && len < datalength; i++)
	len += p[i] + 1;

    return (i != pak->arg_cnt) || (len != datalength);
}

static int acct_reply_looks_bogus(tac_pak_hdr *hdr)
{
    if (hdr->seq_no & 1)
	return -1;
    struct acct_reply *pak = tac_payload(hdr, struct acct_reply *);
    u_int len = TAC_ACCT_REPLY_FIXED_FIELDS_SIZE + ntohs(pak->msg_len) + ntohs(pak->data_len);
    u_int datalength = ntohl(hdr->datalength);
    return (len != datalength);
}


static int aaa_authc_tacacs_ascii(struct aaa *aaa, char *user, char *remoteaddr, char *remotetty, char *pass)
{
    size_t user_len = strlen(user);
    size_t remotetty_len = strlen(remotetty);
    size_t remoteaddr_len = strlen(remoteaddr);
    size_t pass_len = strlen(pass);
    if (user_len & ~0xff || remotetty_len & ~0xff || remoteaddr_len & ~0xff || pass_len & ~0xff)
	return -1;

    ssize_t data_len = TAC_AUTHEN_START_FIXED_FIELDS_SIZE + user_len + remoteaddr_len + remotetty_len;
    tac_pak_hdr *opak = alloca(TAC_PLUS_HDR_SIZE + data_len + pass_len);
    memset(opak, 0, TAC_PLUS_HDR_SIZE + data_len);
    opak->version = TAC_PLUS_MAJOR_VER | TAC_PLUS_MINOR_VER_DEFAULT;
    opak->type = TAC_PLUS_AUTHEN;
    opak->session_id = aaa->conn->id++;
    opak->datalength = htonl(data_len);
    opak->seq_no = 1;
    opak->flags = TAC_PLUS_SINGLE_CONNECT_FLAG | TAC_PLUS_UNENCRYPTED_FLAG;
    struct authen_start *start = tac_payload(opak, struct authen_start *);
    struct authen_cont *cont = tac_payload(opak, struct authen_cont *);
    start->action = TAC_PLUS_AUTHEN_LOGIN;
    start->priv_lvl = TAC_PLUS_PRIV_LVL_MIN;
    start->type = TAC_PLUS_AUTHEN_TYPE_ASCII;
    start->service = aaa->tac_authen_svc;
    start->user_len = user_len;
    start->port_len = remotetty_len;
    start->rem_addr_len = remoteaddr_len;
    u_char *t = (u_char *) start + TAC_AUTHEN_START_FIXED_FIELDS_SIZE;
    memcpy(t, user, user_len);
    t += user_len;
    memcpy(t, remotetty, remotetty_len);
    t += remotetty_len;
    memcpy(t, remoteaddr, remoteaddr_len);
    t += remoteaddr_len;

    if (aaa->conn->key)
	md5_xor(opak, aaa->conn->key, strlen(aaa->conn->key));
    if (conn_write(aaa->conn, opak, TAC_PLUS_HDR_SIZE + data_len) != (TAC_PLUS_HDR_SIZE + data_len))
	return -1;
    tac_pak_hdr hdr;
    if (conn_read(aaa->conn, &hdr, TAC_PLUS_HDR_SIZE) != TAC_PLUS_HDR_SIZE)
	return -1;
    if (hdr.session_id != opak->session_id)
	return -1;
    data_len = ntohl(hdr.datalength);

    tac_pak_hdr *pak = alloca(TAC_PLUS_HDR_SIZE + data_len);
    struct authen_reply *reply = (struct authen_reply *) ((u_char *) pak + TAC_PLUS_HDR_SIZE);
    memcpy(pak, &hdr, TAC_PLUS_HDR_SIZE);
    if (conn_read(aaa->conn, reply, data_len) != data_len)
	return -1;
    if (aaa->conn->key)
	md5_xor(pak, aaa->conn->key, strlen(aaa->conn->key));
    if (authen_reply_looks_bogus(pak))
	return -1;
    if (reply->status != TAC_PLUS_AUTHEN_STATUS_GETPASS)
	return -1;

    opak->seq_no = 3;
    opak->flags = pak->flags;
    data_len = TAC_AUTHEN_CONT_FIXED_FIELDS_SIZE + pass_len;
    opak->datalength = htonl(data_len);
    cont->user_msg_len = ntohs(pass_len);
    cont->user_data_len = 0;
    cont->flags = 0;
    memcpy((u_char *) cont + TAC_AUTHEN_CONT_FIXED_FIELDS_SIZE, pass, pass_len);
    if (aaa->conn->key)
	md5_xor(opak, aaa->conn->key, strlen(aaa->conn->key));
    if (conn_write(aaa->conn, opak, TAC_PLUS_HDR_SIZE + data_len) != (TAC_PLUS_HDR_SIZE + data_len))
	return -1;

    if (conn_read(aaa->conn, &hdr, TAC_PLUS_HDR_SIZE) != TAC_PLUS_HDR_SIZE)
	return -1;
    if (hdr.session_id != opak->session_id)
	return -1;
    data_len = ntohl(hdr.datalength);

    pak = alloca(TAC_PLUS_HDR_SIZE + data_len);
    memset(pak, 0, TAC_PLUS_HDR_SIZE + data_len);
    reply = (struct authen_reply *) ((u_char *) pak + TAC_PLUS_HDR_SIZE);
    memcpy(pak, &hdr, TAC_PLUS_HDR_SIZE);
    if (conn_read(aaa->conn, reply, data_len) != data_len)
	return -1;
    if (aaa->conn->key)
	md5_xor(pak, aaa->conn->key, strlen(aaa->conn->key));
    if (authen_reply_looks_bogus(pak))
	return -1;
    if (reply->status == TAC_PLUS_AUTHEN_STATUS_PASS)
	return 0;

    return -1;
}

static int aaa_authc_tacacs_pap(struct aaa *aaa, char *user, char *remoteaddr, char *remotetty, char *pass)
{
    size_t user_len = strlen(user);
    size_t remotetty_len = strlen(remotetty);
    size_t remoteaddr_len = strlen(remoteaddr);
    size_t pass_len = strlen(pass);
    if (user_len & ~0xff || remotetty_len & ~0xff || remoteaddr_len & ~0xff || pass_len & ~0xff)
	return -1;

    ssize_t data_len = TAC_AUTHEN_START_FIXED_FIELDS_SIZE + user_len + remoteaddr_len + remotetty_len + pass_len;
    tac_pak_hdr *opak = alloca(TAC_PLUS_HDR_SIZE + data_len);
    memset(opak, 0, TAC_PLUS_HDR_SIZE + data_len);
    opak->version = TAC_PLUS_MAJOR_VER | TAC_PLUS_MINOR_VER_ONE;
    opak->type = TAC_PLUS_AUTHEN;
    opak->session_id = aaa->conn->id++;
    opak->datalength = htonl(data_len);
    opak->seq_no = 1;
    opak->flags = TAC_PLUS_SINGLE_CONNECT_FLAG | TAC_PLUS_UNENCRYPTED_FLAG;
    struct authen_start *start = tac_payload(opak, struct authen_start *);
    start->action = TAC_PLUS_AUTHEN_LOGIN;
    start->priv_lvl = TAC_PLUS_PRIV_LVL_MIN;
    start->type = TAC_PLUS_AUTHEN_TYPE_PAP;
    start->service = aaa->tac_authen_svc;
    start->user_len = user_len;
    start->port_len = remotetty_len;
    start->rem_addr_len = remoteaddr_len;
    u_char *t = (u_char *) start + TAC_AUTHEN_START_FIXED_FIELDS_SIZE;
    memcpy(t, user, user_len);
    t += user_len;
    memcpy(t, remotetty, remotetty_len);
    t += remotetty_len;
    memcpy(t, remoteaddr, remoteaddr_len);
    t += remoteaddr_len;
    start->data_len = pass_len;
    memcpy(t, pass, pass_len);

    if (aaa->conn->key)
	md5_xor(opak, aaa->conn->key, strlen(aaa->conn->key));
    if (conn_write(aaa->conn, opak, TAC_PLUS_HDR_SIZE + data_len) != (TAC_PLUS_HDR_SIZE + data_len))
	return -1;
    tac_pak_hdr hdr;
    if (conn_read(aaa->conn, &hdr, TAC_PLUS_HDR_SIZE) != TAC_PLUS_HDR_SIZE)
	return -1;
    if (hdr.session_id != opak->session_id)
	return -1;
    data_len = ntohl(hdr.datalength);

    tac_pak_hdr *pak = alloca(TAC_PLUS_HDR_SIZE + data_len);
    struct authen_reply *reply = (struct authen_reply *) ((u_char *) pak + TAC_PLUS_HDR_SIZE);
    memcpy(pak, &hdr, TAC_PLUS_HDR_SIZE);
    if (conn_read(aaa->conn, reply, data_len) != data_len)
	return -1;
    if (aaa->conn->key)
	md5_xor(pak, aaa->conn->key, strlen(aaa->conn->key));
    if (authen_reply_looks_bogus(pak))
	return -1;
    if (reply->status == TAC_PLUS_AUTHEN_STATUS_PASS)
	return 0;

    return -1;
}

static int aaa_authc_tacacs(struct aaa *aaa, char *user, char *remoteaddr, char *remotetty, char *pass)
{
    if (aaa->tac_authen_pap)
	return aaa_authc_tacacs_pap(aaa, user, remoteaddr, remotetty, pass);

    return aaa_authc_tacacs_ascii(aaa, user, remoteaddr, remotetty, pass);
}

static int aaa_authz_tacacs(struct aaa *aaa, char *user, char *remoteaddr, char *remotetty)
{
    size_t user_len = strlen(user);
    size_t remotetty_len = strlen(remotetty);
    size_t remoteaddr_len = strlen(remoteaddr);
    if (user_len & ~0xff || remotetty_len & ~0xff || remoteaddr_len & ~0xff)
	return -1;

    ssize_t data_len = TAC_AUTHOR_REQ_FIXED_FIELDS_SIZE + user_len + remoteaddr_len + remotetty_len;
    for (int i = 0; i < aaa->oc; i++) {
	if (aaa->ov[i].iov_len & ~0xff)
	    return -1;
	data_len += aaa->ov[i].iov_len + 1;
    }
    tac_pak_hdr *opak = alloca(TAC_PLUS_HDR_SIZE + data_len);
    memset(opak, 0, TAC_PLUS_HDR_SIZE + data_len);
    opak->version = TAC_PLUS_MAJOR_VER | TAC_PLUS_MINOR_VER_DEFAULT;
    opak->type = TAC_PLUS_AUTHOR;
    opak->session_id = aaa->conn->id++;
    opak->datalength = htonl(data_len);
    opak->seq_no = 1;
    opak->flags = TAC_PLUS_SINGLE_CONNECT_FLAG | TAC_PLUS_UNENCRYPTED_FLAG;
    struct author *author = tac_payload(opak, struct author *);
    author->authen_method = aaa->tac_authen_meth;
    author->priv_lvl = TAC_PLUS_PRIV_LVL_MIN;
    author->authen_type = aaa->tac_authen_pap ? TAC_PLUS_AUTHEN_TYPE_PAP : TAC_PLUS_AUTHEN_TYPE_ASCII;
    author->service = aaa->tac_authen_svc;
    author->user_len = user_len;
    author->port_len = remotetty_len;
    author->rem_addr_len = remoteaddr_len;
    u_char *t = (u_char *) author + TAC_AUTHOR_REQ_FIXED_FIELDS_SIZE;
    author->arg_cnt = aaa->oc;
    for (int i = 0; i < aaa->oc; i++) {
	*t++ = aaa->ov[i].iov_len;
    }
    memcpy(t, user, user_len);
    t += user_len;
    memcpy(t, remotetty, remotetty_len);
    t += remotetty_len;
    memcpy(t, remoteaddr, remoteaddr_len);
    t += remoteaddr_len;
    for (int i = 0; i < aaa->oc; i++) {
	memcpy(t, aaa->ov[i].iov_base, aaa->ov[i].iov_len);
	t += aaa->ov[i].iov_len;
    }

    if (aaa->conn->key)
	md5_xor(opak, aaa->conn->key, strlen(aaa->conn->key));
    if (conn_write(aaa->conn, opak, TAC_PLUS_HDR_SIZE + data_len) != (TAC_PLUS_HDR_SIZE + data_len))
	return -1;
    tac_pak_hdr hdr;
    if (conn_read(aaa->conn, &hdr, TAC_PLUS_HDR_SIZE) != TAC_PLUS_HDR_SIZE)
	return -1;
    if (hdr.session_id != opak->session_id)
	return -1;
    data_len = ntohl(hdr.datalength);

    tac_pak_hdr *pak = alloca(TAC_PLUS_HDR_SIZE + data_len);
    struct author_reply *reply = (struct author_reply *) ((u_char *) pak + TAC_PLUS_HDR_SIZE);
    memcpy(pak, &hdr, TAC_PLUS_HDR_SIZE);
    if (conn_read(aaa->conn, reply, data_len) != data_len)
	return -1;
    if (aaa->conn->key)
	md5_xor(pak, aaa->conn->key, strlen(aaa->conn->key));
    if (author_reply_looks_bogus(pak))
	return -1;
    if (reply->status == TAC_PLUS_AUTHOR_STATUS_PASS_ADD || reply->status == TAC_PLUS_AUTHOR_STATUS_PASS_REPL) {
	t = (u_char *) reply + TAC_AUTHOR_REPLY_FIXED_FIELDS_SIZE + ntohs(reply->msg_len) + ntohs(reply->data_len);
	for (u_int i = 0; i < reply->arg_cnt && i < AAA_ATTR_MAX; i++) {
	    aaa->iv[i].iov_len = *t++;
	}
	for (u_int i = 0; i < reply->arg_cnt && i < AAA_ATTR_MAX; i++) {
	    aaa->iv[i].iov_base = calloc(1, aaa->iv[i].iov_len);
	    memcpy(aaa->iv[i].iov_base, t, aaa->iv[i].iov_len);
	    t += aaa->iv[i].iov_len;
	    aaa->ic++;
	}
	return 0;
    }

    return -1;
}

static int aaa_acct_tacacs(struct aaa *aaa, char *user, char *remoteaddr, char *remotetty)
{
    size_t user_len = strlen(user);
    size_t remotetty_len = strlen(remotetty);
    size_t remoteaddr_len = strlen(remoteaddr);
    if (user_len & ~0xff || remotetty_len & ~0xff || remoteaddr_len & ~0xff)
	return -1;

    ssize_t data_len = TAC_ACCT_REQ_FIXED_FIELDS_SIZE + user_len + remoteaddr_len + remotetty_len;
    for (int i = 0; i < aaa->oc; i++) {
	if (aaa->ov[i].iov_len & ~0xff)
	    return -1;
	data_len += aaa->ov[i].iov_len + 1;
    }
    tac_pak_hdr *opak = alloca(TAC_PLUS_HDR_SIZE + data_len);
    memset(opak, 0, TAC_PLUS_HDR_SIZE + data_len);
    opak->version = TAC_PLUS_MAJOR_VER | TAC_PLUS_MINOR_VER_DEFAULT;
    opak->type = TAC_PLUS_ACCT;
    opak->session_id = aaa->conn->id++;
    opak->datalength = htonl(data_len);
    opak->seq_no = 1;
    opak->flags = TAC_PLUS_SINGLE_CONNECT_FLAG | TAC_PLUS_UNENCRYPTED_FLAG;
    struct acct *acct = tac_payload(opak, struct acct *);
    acct->flags = TAC_PLUS_ACCT_FLAG_START;	//FIXME, make this configurable
    acct->authen_method = aaa->tac_authen_meth;
    acct->priv_lvl = TAC_PLUS_PRIV_LVL_MIN;
    acct->authen_service = aaa->tac_authen_svc;
    acct->user_len = user_len;
    acct->port_len = remotetty_len;
    acct->rem_addr_len = remoteaddr_len;
    u_char *t = (u_char *) acct + TAC_ACCT_REQ_FIXED_FIELDS_SIZE;
    acct->arg_cnt = aaa->oc;
    for (int i = 0; i < aaa->oc; i++) {
	*t++ = aaa->ov[i].iov_len;
    }
    memcpy(t, user, user_len);
    t += user_len;
    memcpy(t, remotetty, remotetty_len);
    t += remotetty_len;
    memcpy(t, remoteaddr, remoteaddr_len);
    t += remoteaddr_len;
    for (int i = 0; i < aaa->oc; i++) {
	memcpy(t, aaa->ov[i].iov_base, aaa->ov[i].iov_len);
	t += aaa->ov[i].iov_len;
    }

    if (aaa->conn->key)
	md5_xor(opak, aaa->conn->key, strlen(aaa->conn->key));
    if (conn_write(aaa->conn, opak, TAC_PLUS_HDR_SIZE + data_len) != (TAC_PLUS_HDR_SIZE + data_len))
	return -1;
    tac_pak_hdr hdr;
    if (conn_read(aaa->conn, &hdr, TAC_PLUS_HDR_SIZE) != TAC_PLUS_HDR_SIZE)
	return -1;
    if (hdr.session_id != opak->session_id)
	return -1;
    data_len = ntohl(hdr.datalength);

    tac_pak_hdr *pak = alloca(TAC_PLUS_HDR_SIZE + data_len);
    struct acct_reply *reply = (struct acct_reply *) ((u_char *) pak + TAC_PLUS_HDR_SIZE);
    memcpy(pak, &hdr, TAC_PLUS_HDR_SIZE);
    if (conn_read(aaa->conn, reply, data_len) != data_len)
	return -1;
    if (aaa->conn->key)
	md5_xor(pak, aaa->conn->key, strlen(aaa->conn->key));
    if (acct_reply_looks_bogus(pak))
	return -1;
    if (reply->status == TAC_PLUS_ACCT_STATUS_SUCCESS)
	return 0;
    return -1;
}


static int rad_set_password(u_char **data, size_t *data_len, const char *key, size_t key_len, const u_char *authenticator, char *pass)
{
    *(*data)++ =(u_char) RADIUS_A_USER_PASSWORD;
    (*data_len)--;
    u_char *lenp = (*data)++;
    *lenp = 2;
    u_char digest[16];
    for (int i = 0; *pass && *data_len > 0; i++, pass++, (*data_len)--, (*data)++) {
	if (!(i & 0xf)) {
	    struct iovec iov[2] = {
		{.iov_base = (void *) key,.iov_len = key_len },
		{.iov_base = i ? (void *) (pass - 16) : (void *) authenticator,.iov_len = 16 }
	    };
	    md5v(digest, 16, iov, 2);
	}
	**data = *pass ^ digest[i];
	(*lenp)++;
    }
    if (*pass)
	return -1;
    return 0;
}

static int aaa_got(struct aaa *aaa, u_char * data, size_t data_len);

static int aaa_authc_radius(struct aaa *aaa, char *user, char *remoteaddr, char *remotetty, char *pass)
{
    size_t user_len = strlen(user);
    size_t remotetty_len = strlen(remotetty);
    size_t remoteaddr_len = strlen(remoteaddr);
    size_t pass_len = strlen(pass);
    int radius11 = aaa->conn->alpn && !memcmp(aaa->conn->alpn, "\012radius/1.1", 11);

    if (user_len > 253 || remotetty_len > 253 || remoteaddr_len > 253 || pass_len > 253)
	return -1;

#define RAD_PAK_MAX 4096
    rad_pak_hdr *opkt = alloca(RAD_PAK_MAX);
    memset(opkt, 0, RAD_PAK_MAX);

    opkt->code = RADIUS_CODE_ACCESS_REQUEST;
    if (radius11)
	opkt->token = aaa->conn->id++;
    else
	opkt->identifier = aaa->conn->id++;

    u_char *t = (u_char *) opkt + RADIUS_HDR_SIZE;
    *t++ = (u_char) RADIUS_A_USER_NAME;
    *t++ = (u_char) user_len + 2;
    memcpy(t, user, user_len);
    t += user_len;

    for (int i = 0; i < 16; i += sizeof(int)) {
	*((int *) (opkt->authenticator + i)) = random();
    }
    if (radius11) {
	*t++ = (u_char) RADIUS_A_USER_PASSWORD;
	*t++ = (u_char) pass_len + 2;
	memcpy(t, pass, pass_len);
	t += pass_len;
    } else if (aaa->conn->key) {
	size_t data_len = t - (u_char *) opkt + RAD_PAK_MAX;
	rad_set_password(&t, &data_len, aaa->conn->key, strlen(aaa->conn->key), opkt->authenticator, pass);
    } else
	return -1;

    if (remoteaddr) {
	size_t len = strlen(remoteaddr);
	*t++ = (u_char) RADIUS_A_CALLING_STATION_ID;
	*t++ = (u_char) len + 2;
	memcpy(t, remoteaddr, len);
	t += len;
    }

    if (remotetty) {
	*t++ = (u_char) RADIUS_A_NAS_PORT;
	*t++ = (u_char) 6;
	int n = atoi(remotetty);
	n = htonl(n);
	memcpy(t, &n, 4);
	t += 4;
    }

    for (int i = 0; i < aaa->oc; i++) {
	char *vid_str = alloca(aaa->ov[i].iov_len + 1);
	memcpy(vid_str, aaa->ov[i].iov_base, aaa->ov[i].iov_len + 1);
	char *id_str = strchr(vid_str, ':');

	if (id_str) {
	    *id_str = 0;
	    id_str++;
	} else {
	    id_str = vid_str;
	    vid_str = "";
	}

	char *v_str = strchr(id_str, '=');

	if (!v_str) {
	    fprintf(stderr, "RADIUS attribute '%s': missing value\n", (char *) aaa->ov[i].iov_base);
	    exit(-1);
	}
	*v_str++ = 0;

	struct rad_dict *dict = rad_dict_lookup_by_name(vid_str);
	if (!dict) {
	    fprintf(stderr, "RADIUS dictionary '%s' unknown\n", vid_str);
	    exit(-1);
	}

	struct rad_dict_attr *attr = rad_dict_attr_lookup_by_name(dict, id_str);
	if (!attr) {
	    fprintf(stderr, "RADIUS attribute '%s' unknown\n", (char *) aaa->ov[i].iov_base);
	    exit(-1);
	}

	u_char *vlenp = NULL;
	if (*vid_str) {
	    *t++ = RADIUS_A_VENDOR_SPECIFIC;
	    vlenp = t;
	    *t++ = 6;
	    u_char u = htonl(attr->dict->id);
	    memcpy(t, &u, 4);
	    t += 4;
	}

	u_char *t_start = t;

	if (attr->type == S_integer || attr->type == S_time || attr->type == S_enum) {
	    u_int u;
	    if (isdigit(*v_str)) {
		u = atoi(v_str);
	    } else {
		struct rad_dict_val *val = rad_dict_val_lookup_by_name(attr, v_str);
		if (!val) {
		    fprintf(stderr, "RADIUS value '%s' not found (attribute: %s)", v_str, attr->name.txt);
		    exit(-1);
		}
		u = val->id;
	    }
	    *t++ = attr->id;
	    *t++ = 6;
	    u = htonl(u);
	    memcpy(t, &u, 4);
	    t += 4;
	} else if (attr->type == S_string_keyword) {
	    size_t val_len = strlen(v_str);
	    *t++ = attr->id;
	    *t += 2 + val_len;
	    memcpy(t, v_str, val_len);
	    t += val_len;
	} else if (attr->type == S_address || attr->type == S_ipaddr || attr->type == S_ipv4addr) {
	    *t++ = attr->id;
	    *t++ = 6;
	    u_char ipv4[4];
	    if (!inet_pton(AF_INET, v_str, ipv4)) {
		fprintf(stderr, "IPv4 address %s not recognized\n", v_str);
		exit(-1);
	    }
	    memcpy(t, ipv4, 4);
	    t += 4;
	} else if (attr->type == S_ipv6addr) {
	    *t++ = attr->id;
	    *t++ = 18;
	    u_char ipv6[16];
	    if (!inet_pton(AF_INET6, v_str, ipv6)) {
		fprintf(stderr, "IPv6 address %s not recognized\n", v_str);
		exit(-1);
	    }
	    memcpy(t, ipv6, 16);
	    t += 16;
	}
	if (vlenp)
	    *vlenp = t - t_start;
    }

    opkt->length = htons(t - (u_char *) opkt);
    if (!radius11) {
	if (t + 18 - (u_char *) opkt >= RAD_PAK_MAX)
	    return -1;
	*t++ = RADIUS_A_MESSAGE_AUTHENTICATOR;
	*t++ = 18;
	u_char *ma = t;
	memset(t, 0, 16);
	t += 16;
	u_int ma_len = 16;
	opkt->length = htons(t - (u_char *) opkt);
	HMAC(EVP_md5(), aaa->conn->key, strlen(aaa->conn->key), (u_char *) opkt, t - (u_char *) opkt, ma, &ma_len);
    }

    int tries = aaa->conn->retries + 1;
  retry:
    if (conn_write(aaa->conn, opkt, t - (u_char *) opkt) != t - (u_char *) opkt)
	return -1;
    tries--;
    rad_pak_hdr *ipkt = alloca(RAD_PAK_MAX);
    if (conn_read(aaa->conn, ipkt, RADIUS_HDR_SIZE) != RADIUS_HDR_SIZE) {
	if (tries)
	    goto retry;
	return -1;
    }
    ssize_t ipkt_len = ntohs(ipkt->length);

    if (RADIUS_HDR_SIZE + ipkt_len > RAD_PAK_MAX)
	return -1;
    if (conn_read(aaa->conn, (u_char *) ipkt + RADIUS_HDR_SIZE, ipkt_len - RADIUS_HDR_SIZE) != (ssize_t) (ipkt_len - RADIUS_HDR_SIZE))
	return -1;

    if (radius11) {
	if (opkt->token != ipkt->token)
	    return -1;
    } else {
	if (opkt->identifier != ipkt->identifier)
	    return -1;
	u_char ia[MD5_LEN];
	memcpy(ia, ipkt->authenticator, MD5_LEN);
	memset(ipkt->authenticator, 0, MD5_LEN);
	struct iovec iov[4] = {
	    {.iov_base = ipkt, 4 },
	    {.iov_base = opkt->authenticator,.iov_len = 16 },
	    {.iov_base = RADIUS_DATA(ipkt),.iov_len = RADIUS_DATA_LEN(ipkt) },
	    {.iov_base = aaa->conn->key,.iov_len = strlen(aaa->conn->key) }
	};
	u_char a[MD5_LEN];
	md5v(a, MD5_LEN, iov, 4);
	if (memcmp(a, ia, MD5_LEN))
	    return -1;

	memcpy(ipkt->authenticator, opkt->authenticator, MD5_LEN);

	u_char ima[16];
	u_char *t = (u_char *) ipkt + RADIUS_HDR_SIZE;
	int ma_found = 0;
	while (t < (u_char *) ipkt + ipkt_len) {
	    if (*t == RADIUS_A_MESSAGE_AUTHENTICATOR) {
		if (*(t + 1) == 18 && t + *(t + 1) > (u_char *) ipkt + ipkt_len)
		    return -1;
		memcpy(ima, t + 2, 16);
		memset(t + 2, 0, 16);
		ma_found = 1;
		break;
	    }
	    t++;
	    if (t >= (u_char *) ipkt + ipkt_len)
		return -1;
	    if (!*t)
		return -1;
	    t += *t - 1;
	}
	if (!ma_found)
	    return -1;

	u_char cma[16];
	u_int ma_len = 16;
	HMAC(EVP_md5(), aaa->conn->key, strlen(aaa->conn->key), (u_char *) ipkt, ipkt_len, cma, &ma_len);
	if (memcmp(ima, cma, 16))
	    return -1;
    }
    if (ipkt->code == RADIUS_CODE_ACCESS_ACCEPT) {
	u_char *data = RADIUS_DATA(ipkt);
	size_t data_len = RADIUS_DATA_LEN(ipkt);
	char *buf = NULL;
	while ((buf = rad_attr_val_dump1(NULL, &data, &data_len))) {
	    size_t buf_len = strlen(buf) + 1;
	    u_char *d = calloc(1, buf_len + 1);
	    memcpy(d, buf, buf_len + 1);
	    aaa_got(aaa, d, buf_len + 1);
	    free(buf);
	}
	return 0;
    }

    return -1;
}

static int aaa_acct_radius(struct aaa *aaa, char *user, char *remoteaddr, char *remotetty)
{
    size_t user_len = strlen(user);
    size_t remotetty_len = strlen(remotetty);
    size_t remoteaddr_len = strlen(remoteaddr);
    int radius11 = aaa->conn->alpn && !memcmp(aaa->conn->alpn, "\012radius/1.1", 11);

    if (user_len > 253 || remotetty_len > 253 || remoteaddr_len > 253)
	return -1;

#define RAD_PAK_MAX 4096
    rad_pak_hdr *opkt = alloca(RAD_PAK_MAX);
    memset(opkt, 0, RAD_PAK_MAX);

    opkt->code = RADIUS_CODE_ACCOUNTING_REQUEST;
    if (radius11)
	opkt->token = aaa->conn->id++;
    else
	opkt->identifier = aaa->conn->id++;

    u_char *t = (u_char *) opkt + RADIUS_HDR_SIZE;
    *t++ = (u_char) RADIUS_A_USER_NAME;
    *t++ = (u_char) user_len + 2;
    memcpy(t, user, user_len);
    t += user_len;

    for (int i = 0; i < 16; i += sizeof(int)) {
	*((int *) (opkt->authenticator + i)) = random();
    }

    if (remoteaddr) {
	size_t len = strlen(remoteaddr);
	*t++ = (u_char) RADIUS_A_CALLING_STATION_ID;
	*t++ = (u_char) len + 2;
	memcpy(t, remoteaddr, len);
	t += len;
    }

    if (remotetty) {
	*t++ = (u_char) RADIUS_A_NAS_PORT;
	*t++ = (u_char) 6;
	int n = atoi(remotetty);
	n = htonl(n);
	memcpy(t, &n, 4);
	t += 4;
    }

    for (int i = 0; i < aaa->oc; i++) {
	char *vid_str = alloca(aaa->ov[i].iov_len + 1);
	memcpy(vid_str, aaa->ov[i].iov_base, aaa->ov[i].iov_len + 1);
	char *id_str = strchr(vid_str, ':');

	if (id_str) {
	    *id_str = 0;
	    id_str++;
	} else {
	    id_str = vid_str;
	    vid_str = "";
	}

	char *v_str = strchr(id_str, '=');

	if (!v_str) {
	    fprintf(stderr, "RADIUS attribute '%s': missing value\n", (char *) aaa->ov[i].iov_base);
	    exit(-1);
	}
	*v_str++ = 0;

	struct rad_dict *dict = rad_dict_lookup_by_name(vid_str);
	if (!dict) {
	    fprintf(stderr, "RADIUS dictionary '%s' unknown\n", vid_str);
	    exit(-1);
	}

	struct rad_dict_attr *attr = rad_dict_attr_lookup_by_name(dict, id_str);
	if (!attr) {
	    fprintf(stderr, "RADIUS attribute '%s' unknown\n", (char *) aaa->ov[i].iov_base);
	    exit(-1);
	}

	u_char *vlenp = NULL;
	if (*vid_str) {
	    *t++ = RADIUS_A_VENDOR_SPECIFIC;
	    vlenp = t;
	    *t++ = 6;
	    u_char u = htonl(attr->dict->id);
	    memcpy(t, &u, 4);
	    t += 4;
	}

	u_char *t_start = t;

	if (attr->type == S_integer || attr->type == S_time || attr->type == S_enum) {
	    u_int u;
	    if (isdigit(*v_str)) {
		u = atoi(v_str);
	    } else {
		struct rad_dict_val *val = rad_dict_val_lookup_by_name(attr, v_str);
		if (!val) {
		    fprintf(stderr, "RADIUS value '%s' not found (attribute: %s)", v_str, attr->name.txt);
		    exit(-1);
		}
		u = val->id;
	    }
	    *t++ = attr->id;
	    *t++ = 6;
	    u = htonl(u);
	    memcpy(t, &u, 4);
	    t += 4;
	} else if (attr->type == S_string_keyword) {
	    size_t val_len = strlen(v_str);
	    *t++ = attr->id;
	    *t += 2 + val_len;
	    memcpy(t, v_str, val_len);
	    t += val_len;
	} else if (attr->type == S_address || attr->type == S_ipaddr || attr->type == S_ipv4addr) {
	    *t++ = attr->id;
	    *t++ = 6;
	    u_char ipv4[4];
	    if (!inet_pton(AF_INET, v_str, ipv4)) {
		fprintf(stderr, "IPv4 address %s not recognized\n", v_str);
		exit(-1);
	    }
	    memcpy(t, ipv4, 4);
	    t += 4;
	} else if (attr->type == S_ipv6addr) {
	    *t++ = attr->id;
	    *t++ = 18;
	    u_char ipv6[16];
	    if (!inet_pton(AF_INET6, v_str, ipv6)) {
		fprintf(stderr, "IPv6 address %s not recognized\n", v_str);
		exit(-1);
	    }
	    memcpy(t, ipv6, 16);
	    t += 16;
	}
	if (vlenp)
	    *vlenp = t - t_start;
    }

    opkt->length = htons(t - (u_char *) opkt);
    if (!radius11) {
	if (t + 18 - (u_char *) opkt >= RAD_PAK_MAX)
	    return -1;
	*t++ = RADIUS_A_MESSAGE_AUTHENTICATOR;
	*t++ = 18;
	u_char *ma = t;
	memset(t, 0, 16);
	t += 16;
	u_int ma_len = 16;
	opkt->length = htons(t - (u_char *) opkt);
	HMAC(EVP_md5(), aaa->conn->key, strlen(aaa->conn->key), (u_char *) opkt, t - (u_char *) opkt, ma, &ma_len);
    }

    int tries = aaa->conn->retries + 1;
  retry:
    if (conn_write(aaa->conn, opkt, t - (u_char *) opkt) != t - (u_char *) opkt)
	return -1;
    tries--;
    rad_pak_hdr *ipkt = alloca(RAD_PAK_MAX);
    if (conn_read(aaa->conn, ipkt, RADIUS_HDR_SIZE) != RADIUS_HDR_SIZE) {
	if (tries)
	    goto retry;
	return -1;
    }
    ssize_t ipkt_len = ntohs(ipkt->length);

    if (RADIUS_HDR_SIZE + ipkt_len > RAD_PAK_MAX)
	return -1;
    if (conn_read(aaa->conn, (u_char *) ipkt + RADIUS_HDR_SIZE, ipkt_len - RADIUS_HDR_SIZE) != (ssize_t) (ipkt_len - RADIUS_HDR_SIZE))
	return -1;

    if (radius11) {
	if (opkt->token != ipkt->token)
	    return -1;
    } else {
	if (opkt->identifier != ipkt->identifier)
	    return -1;
	u_char ia[MD5_LEN];
	memcpy(ia, ipkt->authenticator, MD5_LEN);
	memset(ipkt->authenticator, 0, MD5_LEN);
	struct iovec iov[4] = {
	    {.iov_base = ipkt, 4 },
	    {.iov_base = opkt->authenticator,.iov_len = 16 },
	    {.iov_base = RADIUS_DATA(ipkt),.iov_len = RADIUS_DATA_LEN(ipkt) },
	    {.iov_base = aaa->conn->key,.iov_len = strlen(aaa->conn->key) }
	};
	u_char a[MD5_LEN];
	md5v(a, MD5_LEN, iov, 4);
	if (memcmp(a, ia, MD5_LEN))
	    return -1;

	memcpy(ipkt->authenticator, opkt->authenticator, MD5_LEN);
	u_char ima[16];
	u_char *t = (u_char *) ipkt + RADIUS_HDR_SIZE;
	int ma_found = 0;
	while (t < (u_char *) ipkt + ipkt_len) {
	    if (*t == RADIUS_A_MESSAGE_AUTHENTICATOR) {
		if (*(t + 1) == 18 && t + *(t + 1) > (u_char *) ipkt + ipkt_len)
		    return -1;
		memcpy(ima, t + 2, 16);
		memset(t + 2, 0, 16);
		ma_found = 1;
		break;
	    }
	    t++;
	    if (t >= (u_char *) ipkt + ipkt_len)
		return -1;
	    if (!*t)
		return -1;
	    t += *t - 1;
	}
	if (ma_found) {
	    // message authenticator is optional for accounting, but will be validated if present
	    u_char cma[16];
	    u_int ma_len = 16;
	    HMAC(EVP_md5(), aaa->conn->key, strlen(aaa->conn->key), (u_char *) ipkt, ipkt_len, cma, &ma_len);
	    if (memcmp(ima, cma, 16))
		return -1;
	}
    }
    if (ipkt->code == RADIUS_CODE_ACCOUNTING_RESPONSE) {
	u_char *data = RADIUS_DATA(ipkt);
	size_t data_len = RADIUS_DATA_LEN(ipkt);
	char *buf = NULL;
	while ((buf = rad_attr_val_dump1(NULL, &data, &data_len))) {
	    size_t buf_len = strlen(buf) + 1;
	    u_char *d = calloc(1, buf_len + 1);
	    memcpy(d, buf, buf_len + 1);
	    aaa_got(aaa, d, buf_len + 1);
	    free(buf);
	}
	return 0;
    }

    return -1;
}

int aaa_authc(struct aaa *aaa, char *user, char *remoteaddr, char *remotetty, char *pass)
{
    switch (aaa->conn->protocol) {
    case S_radius_tls:
    case S_radius_dtls:
    case S_radius_udp:
    case S_radius_tcp:
	return aaa_authc_radius(aaa, user, remoteaddr, remotetty, pass);
    case S_tacacs_tls:
    case S_tacacs_tcp:
	return aaa_authc_tacacs(aaa, user, remoteaddr, remotetty, pass);
    default:
	return -1;
    }
}

int aaa_authz(struct aaa *aaa, char *user, char *remoteaddr, char *remotetty)
{
    switch (aaa->conn->protocol) {
    case S_tacacs_tls:
    case S_tacacs_tcp:
	return aaa_authz_tacacs(aaa, user, remoteaddr, remotetty);
    default:
	return -1;
    }
}

int aaa_acct(struct aaa *aaa, char *user, char *remoteaddr, char *remotetty)
{
    switch (aaa->conn->protocol) {
    case S_radius_tls:
    case S_radius_dtls:
    case S_radius_udp:
    case S_radius_tcp:
	return aaa_acct_radius(aaa, user, remoteaddr, remotetty);
    case S_tacacs_tls:
    case S_tacacs_tcp:
	return aaa_acct_tacacs(aaa, user, remoteaddr, remotetty);
    default:
	return -1;
    }
}

int aaa_set(struct aaa *aaa, u_char *data, size_t data_len)
{
    if (aaa->oc < AAA_ATTR_MAX) {
	aaa->ov[aaa->oc].iov_base = calloc(1, data_len);
	memcpy(aaa->ov[aaa->oc].iov_base, data, data_len);
	aaa->ov[aaa->oc].iov_len = data_len;
	aaa->oc++;
	return 0;
    }
    return -1;
}

static int aaa_got(struct aaa *aaa, u_char *data, size_t data_len)
{
    if (aaa->ic < AAA_ATTR_MAX) {
	aaa->iv[aaa->ic].iov_base = calloc(1, data_len);
	memcpy(aaa->iv[aaa->ic].iov_base, data, data_len);
	aaa->iv[aaa->ic].iov_len = data_len;
	aaa->ic++;
	return 0;
    }
    return -1;
}

int aaa_get(struct aaa *aaa, u_char *prefix, size_t prefix_len, int *start, u_char **data, size_t *data_len)
{
    int i = 0;
    if (start)
	i = *start;
    for (; i < aaa->ic; i++) {
	if (aaa->iv[i].iov_base && aaa->iv[i].iov_len >= prefix_len && !memcmp(aaa->iv[i].iov_base, prefix, prefix_len)) {
	    *data = aaa->iv[i].iov_base;
	    *data_len = aaa->iv[i].iov_len;
	    *start = i + 1;
	    return 0;
	}
    }
    return -1;
}

void aaa_set_tac_authen_pap(struct aaa *aaa, int onoff)
{
    aaa->tac_authen_pap = onoff;
}

void aaa_set_tac_authen_svc(struct aaa *aaa, int svc)
{
    aaa->tac_authen_svc = svc;
}

void aaa_set_tac_authen_meth(struct aaa *aaa, int meth)
{
    aaa->tac_authen_meth = meth;
}

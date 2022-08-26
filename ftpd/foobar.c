/*
 * foobar.c
 * (C)1998-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * RFC 1639 (FTP Operation Over Big Address Records)
 * RFC 2428 (FTP Extensions for IPv6 and NATs)
 * RFC 959  (FTP)
 * RFC 1700 (Assigned Numbers)
 *
 * $Id$
 *
 */

#include "headers.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

#define FOOBAR_AF_IP            4	/* IP (IPv4)              */
#define FOOBAR_AF_ST            5	/* ST Datagram Mode       */
#define FOOBAR_AF_SIP           6	/* SIP (IPv6)             */
#define FOOBAR_AF_TPIX          7	/* TP/IX                  */
#define FOOBAR_AF_PIP           8	/* PIP                    */
#define FOOBAR_AF_TUBA          9	/* TUBA                   */
#define FOOBAR_AF_IPX           16	/* Novell IPX             */

#define RFC2428_AF_IP           1	/* IP (IP version 4)      */
#define RFC2428_AF_IP6          2	/* IP6 (IP version 6)     */

struct foobar_af_mapping_s {
    int foobar_af;
    int af;
};

struct foobar_af_mapping_s foobar_af_mapping[] = {
#ifdef AF_INET
    { FOOBAR_AF_IP, AF_INET, },
#endif
#ifdef AF_INET6
    { FOOBAR_AF_SIP, AF_INET6, },
#endif
    { -1, -1, },
};

struct rfc2428_af_mapping_s {
    int rfc2428_af;
    int af;
};

struct rfc2428_af_mapping_s rfc2428_af_mapping[] = {
#ifdef AF_INET
    { RFC2428_AF_IP, AF_INET, },
#endif
#ifdef AF_INET6
    { RFC2428_AF_IP6, AF_INET6, },
#endif
    { -1, -1, },
};

int foobar2af(int af)
{
    struct foobar_af_mapping_s *m = foobar_af_mapping;
    for (; m->foobar_af != -1; m++)
	if (m->foobar_af == af)
	    return m->af;
    return -1;
}

int af2foobar(int af)
{
    struct foobar_af_mapping_s *m = foobar_af_mapping;
    for (; m->foobar_af != -1; m++)
	if (m->af == af)
	    return m->foobar_af;
    return -1;
}

int rfc2428_2_af(int af)
{
    struct rfc2428_af_mapping_s *m = rfc2428_af_mapping;

    for (; m->rfc2428_af != -1; m++)
	if (m->rfc2428_af == af)
	    return m->af;
    return -1;
}

char *print_rfc2428_families(char *s, size_t len)
{
    char *t = s;
    struct rfc2428_af_mapping_s *m = rfc2428_af_mapping;

    for (; m->rfc2428_af != -1; m++) {
	if (s != t)
	    *t++ = ',';
	t += snprintf(t, (size_t) (s + len - t), "%d", m->rfc2428_af);
    }
    return s;
}

char *print_foobar_families(char *s, size_t len)
{
    char *t = s;
    struct foobar_af_mapping_s *m = foobar_af_mapping;

    for (; m->foobar_af != -1; m++) {
	if (s != t)
	    *t++ = ',';
	t += snprintf(t, (size_t) (s + len - t), "%d", m->foobar_af);
    }
    return s;
}

int af2rfc2428(int af)
{
    struct rfc2428_af_mapping_s *m = rfc2428_af_mapping;
    for (; m->rfc2428_af != -1; m++)
	if (m->af == af)
	    return m->rfc2428_af;
    return -1;
}

/* foobar_eval() -- evaluate <long-host-port> */
/* returns foobar address family, -1 on error */
/* char *long-host-port, void *addr, int *addrlen, void *port, int *portlen */
int foobar_eval(sockaddr_union * sa, char *s)
{
    u_char arr[513];
    int length = 0;

    DebugIn(DEBUG_COMMAND);

    if (!s) {
	Debug((DEBUG_COMMAND, "- %s: arg == NULL\n", __func__));
	return -1;
    }

    memset(arr, 0, (size_t) 513);

    while (*s && isspace((int) *s))
	s++;

    for (; *s && !isspace((int) *s) && length < 512; s++)
	if (isdigit((int) *s)) {
	    arr[length] *= 10;
	    arr[length] += (u_char) * s - '0';
	} else if (*s == ',')
	    length++;
	else {
	    Debug((DEBUG_COMMAND, "- %s: invalid char\n", __func__));
	    return -1;
	}

    if (++length != arr[1] + 3 + arr[arr[1] + 2]) {
	Debug((DEBUG_COMMAND, "- %s: consistency check failed\n", __func__));
	return -1;
    }

    memset(sa, 0, sizeof(sockaddr_union));
    sa->sa.sa_family = foobar2af(arr[1]);

    switch (sa->sa.sa_family) {
#ifdef AF_INET
    case AF_INET:
	memcpy(&sa->sin.sin_addr, arr + 2, (size_t) 4);
	memcpy(&sa->sin.sin_port, arr + arr[1] + 3, (size_t) 2);
	return sa->sa.sa_family;
#endif				/* AF_INET */
#ifdef AF_INET6
    case AF_INET6:
	memcpy(&sa->sin6.sin6_addr, arr + 2, (size_t) 16);
	memcpy(&sa->sin6.sin6_port, arr + arr[1] + 3, (size_t) 2);
	return sa->sa.sa_family;
#endif				/* AF_INET6 */
    }

    Debug((DEBUG_COMMAND, "- %s: af = %d\n", __func__, arr[0]));
    return -2;
}

char *foobar_str(sockaddr_union * sa, char *res, size_t reslen)
{
    char *s = res;
    int al, pl;
    u_char *a, *p;

    switch (sa->sa.sa_family) {
#ifdef AF_INET
    case AF_INET:
	al = 4, pl = 2;
	a = (u_char *) & sa->sin.sin_addr;
	p = (u_char *) & sa->sin.sin_port;
	break;
#endif
#ifdef AF_INET6
    case AF_INET6:
	al = 16, pl = 2;
	a = (u_char *) & sa->sin6.sin6_addr;
	p = (u_char *) & sa->sin6.sin6_port;
	break;
#endif
    default:
	return "(NULL)";
    }

    s += snprintf(s, (size_t) (res + reslen - s), "%d,%u", af2foobar(sa->sa.sa_family), (u_int) al);

    while (al--)
	s += snprintf(s, (size_t) (res + reslen - s), ",%u", (u_int) * a++);

    s += snprintf(s, (size_t) (res + reslen - s), ",%u", (u_int) pl);

    while (pl--)
	s += snprintf(s, (size_t) (res + reslen - s), ",%u", (u_int) * p++);

    return res;
}

int rfc2428_eval(sockaddr_union * sa, char *in)
{
    char *s = alloca(strlen(in) + 1);
    char delimiter;
    int proto = -1;
    char *net_prt = NULL;
    char *net_addr = NULL;
    char *tcp_port = NULL;
    char *remainder = NULL;
    int af;

    DebugIn(DEBUG_COMMAND);

    strcpy(s, in);

    if (!s) {
	Debug((DEBUG_COMMAND, "- %s: arg == NULL\n", __func__));
	return -1;
    }

    delimiter = s[0];
    net_prt = s + 1;
    if ((net_addr = strchr(net_prt, delimiter))) {
	*net_addr++ = 0;
	if ((tcp_port = strchr(net_addr, delimiter))) {
	    *tcp_port++ = 0;

	    if ((remainder = strchr(tcp_port, delimiter)))
		*remainder = 0;
	}
    }

    if (!remainder) {
	Debug((DEBUG_COMMAND, "- %s: parse error\n", __func__));
	return -1;
    }

    proto = atoi(net_prt);

    af = rfc2428_2_af(proto);
    if (af < 0) {
	Debug((DEBUG_COMMAND, "- %s: unknown protocol\n", __func__));
	return -2;
    }

    if (!tcp_port || su_pton_p(sa, net_addr, atoi(tcp_port)) || af != sa->sa.sa_family) {
	Debug((DEBUG_COMMAND, "- %s:  error\n", __func__));
	return -1;
    }

    Debug((DEBUG_COMMAND, "- %s: af = %d\n", __func__, proto));
    return sa->sa.sa_family;
}

int rfc959_eval(sockaddr_union * sa, char *s)
{
    u_char arr[6];
    int length = 0;

    DebugIn(DEBUG_COMMAND);

    if (!s) {
	Debug((DEBUG_COMMAND, "- %s: arg == NULL\n", __func__));
	return -1;
    }

    memset(arr, 0, (size_t) 6);

    while (*s && isspace((int) *s))
	s++;

    for (; *s && !isspace((int) *s) && length < 6; s++)
	if (isdigit((int) *s)) {
	    arr[length] *= 10;
	    arr[length] += (u_char) * s - '0';
	} else if (*s == ',')
	    length++;
	else {
	    Debug((DEBUG_COMMAND, "- %s: invalid char\n", __func__));
	    return -1;
	}

    if (length != 5) {
	Debug((DEBUG_COMMAND, "- %s: consistency check failed\n", __func__));
	return -1;
    }

    memset(sa, 0, sizeof(sockaddr_union));
    sa->sa.sa_family = AF_INET;
    memcpy(&sa->sin.sin_addr, arr, (size_t) 4);
    memcpy(&sa->sin.sin_port, arr + 4, (size_t) 2);

    Debug((DEBUG_COMMAND, "- %s: af = AF_INET\n", __func__));
    return AF_INET;
}

char *rfc959_str(sockaddr_union * sa, char *res, size_t reslen)
{
    char *s = res;
    int al = 4, pl = 2;
    u_char *a = NULL, *p = NULL;
    switch (sa->sa.sa_family) {
#ifdef AF_INET
    case AF_INET:
	a = (u_char *) & sa->sin.sin_addr;
	p = (u_char *) & sa->sin.sin_port;
	break;
#endif				/* AF_INET */
#ifdef AF_INET6
    case AF_INET6:
	a = (u_char *) & sa->sin6.sin6_addr + 12;
	p = (u_char *) & sa->sin6.sin6_port;
	break;
#endif				/* AF_INET6 */
    default:
	return "";
    }

    for (; al; a++, al--) {
	if (al != 4)
	    *s++ = ',';
	s += snprintf(s, (size_t) (res + reslen - s), "%u", (u_int) * a);
    }

    for (; pl; p++, pl--)
	s += snprintf(s, (size_t) (res + reslen - s), ",%u", (u_int) * p);

    return res;
}

char *rfc2428_str(sockaddr_union * sa, char *res, size_t reslen)
{
    char buf[INET6_ADDRSTRLEN];
    char *s = res;
    char delimiter = '|';
    u_short p;

    *s++ = delimiter;

    switch (sa->sa.sa_family) {
#ifdef AF_INET
    case AF_INET:
	*s++ = RFC2428_AF_IP + '0';
	p = sa->sin.sin_port;
	break;
#endif
#ifdef AF_INET6
    case AF_INET6:
	*s++ = RFC2428_AF_IP6 + '0';
	p = sa->sin6.sin6_port;
	break;
#endif
    default:
	return "(NULL)";
    }

    snprintf(s, (size_t) (res + reslen - s - 1), "%c%s%c%d%c", delimiter, su_ntop(sa, buf, (socklen_t) sizeof(buf)), delimiter, ntohs(p), delimiter);

    return res;
}

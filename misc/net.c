/*
 * net.c
 * (C)1999-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#include "misc/sysconf.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdlib.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <sys/stat.h>
#include "misc/net.h"

static const char rcsid[] __attribute__((used)) = "$Id$";

uint16_t su_get_port(sockaddr_union *sa)
{
    switch (sa->sa.sa_family) {
#ifdef AF_INET
    case AF_INET:
	return ntohs(sa->sin.sin_port);
#endif				/* AF_INET */
#ifdef AF_INET6
    case AF_INET6:
	return ntohs(sa->sin6.sin6_port);
#endif				/* AF_INET6 */
    }
    return 0;
}

int su_set_port(sockaddr_union *sa, uint16_t port)
{
    switch (sa->sa.sa_family) {
#ifdef AF_INET
    case AF_INET:
	sa->sin.sin_port = htons(port);
	return 0;
#endif				/* AF_INET */
#ifdef AF_INET6
    case AF_INET6:
	sa->sin6.sin6_port = htons(port);
	return 0;
#endif				/* AF_INET6 */
    }
    return -1;
}

int su_convert(sockaddr_union *sa, u_int af)
{
    if (sa->sa.sa_family == af)
	return 0;

#if defined(AF_INET) && defined(AF_INET6)
    if (sa->sa.sa_family == AF_INET && af == AF_INET6) {
	sockaddr_union su;
	su = *sa;
	memset(sa, 0, sizeof(sockaddr_union));
	sa->sin6.sin6_port = su.sin.sin_port;
	sa->sa.sa_family = AF_INET6;
	if (!su_copy_addr(sa, &su))
	    return 0;
	*sa = su;
	return -1;
    }

    if (sa->sa.sa_family == AF_INET6 && af == AF_INET) {
	if (IN6_IS_ADDR_V4MAPPED(&sa->sin6.sin6_addr)) {
	    sockaddr_union su;
	    su = *sa;
	    memset(sa, 0, sizeof(sockaddr_union));
	    sa->sin.sin_port = su.sin6.sin6_port;
	    sa->sa.sa_family = AF_INET;
	    if (!su_copy_addr(sa, &su))
		return 0;
	    *sa = su;
	}
	return -1;
    }
#endif

    return -1;
}

int su_equal_addr(sockaddr_union *dst, sockaddr_union *src)
{
    if (dst->sa.sa_family == src->sa.sa_family) {
	switch (dst->sa.sa_family) {
#ifdef AF_UNIX
	case AF_UNIX:
	    return !strcmp(dst->sun.sun_path, src->sun.sun_path);
#endif				/* AF_UNIX */
#ifdef AF_INET
	case AF_INET:
	    return (dst->sin.sin_addr.s_addr == src->sin.sin_addr.s_addr);
#endif				/* AF_INET */
#ifdef AF_INET6
	case AF_INET6:
	    return IN6_ARE_ADDR_EQUAL(&dst->sin6.sin6_addr, &src->sin6.sin6_addr);
#endif				/* AF_INET6 */
	}
    }
#if defined(AF_INET) && defined(AF_INET6)
    if (dst->sa.sa_family == AF_INET && src->sa.sa_family == AF_INET6)
	return (IN6_IS_ADDR_V4MAPPED(&src->sin6.sin6_addr) && dst->sin.sin_addr.s_addr == src->sin6.sin6_addr.s6_addr32[3]);

    if (dst->sa.sa_family == AF_INET6 && src->sa.sa_family == AF_INET)
	return (IN6_IS_ADDR_V4MAPPED(&dst->sin6.sin6_addr) && dst->sin6.sin6_addr.s6_addr32[3] == src->sin.sin_addr.s_addr);
#endif				/* defined(AF_INET) && defined(AF_INET6) */

    return 0;
}

int su_equal(sockaddr_union *dst, sockaddr_union *src)
{
    return (su_equal_addr(dst, src)
	    && su_get_port(dst) == su_get_port(src));
}

int su_cmp_addr(sockaddr_union *dst, sockaddr_union *src)
{
    if (dst->sa.sa_family == src->sa.sa_family) {
	switch (dst->sa.sa_family) {
#ifdef AF_UNIX
	case AF_UNIX:
	    return strcmp(dst->sun.sun_path, src->sun.sun_path);
#endif				/* AF_UNIX */
#ifdef AF_INET
	case AF_INET:
	    if (dst->sin.sin_addr.s_addr < src->sin.sin_addr.s_addr)
		return -1;
	    if (dst->sin.sin_addr.s_addr > src->sin.sin_addr.s_addr)
		return +1;
	    return 0;
#endif				/* AF_INET */
#ifdef AF_INET6
	case AF_INET6:
	    return memcmp(&dst->sin6.sin6_addr, &src->sin6.sin6_addr, (size_t) 16);
#endif				/* AF_INET6 */
	}
    }
#if defined(AF_INET) && defined(AF_INET6)
    if (dst->sa.sa_family == AF_INET && src->sa.sa_family == AF_INET6) {
	if (!IN6_IS_ADDR_V4MAPPED(&src->sin6.sin6_addr))
	    return -1;
	if (dst->sin.sin_addr.s_addr < src->sin6.sin6_addr.s6_addr32[3])
	    return -1;
	if (dst->sin.sin_addr.s_addr > src->sin6.sin6_addr.s6_addr32[3])
	    return +1;
	return 0;
    }

    if (dst->sa.sa_family == AF_INET6 && src->sa.sa_family == AF_INET) {
	if (!IN6_IS_ADDR_V4MAPPED(&dst->sin6.sin6_addr))
	    return -1;
	if (dst->sin6.sin6_addr.s6_addr32[3] < src->sin.sin_addr.s_addr)
	    return -1;
	if (dst->sin6.sin6_addr.s6_addr32[3] > src->sin.sin_addr.s_addr)
	    return +1;
	return 0;
    }
#endif				/* defined(AF_INET) && defined(AF_INET6) */
    return -1;
}

int su_cmp(sockaddr_union *dst, sockaddr_union *src)
{
    int r = su_cmp_addr(dst, src);
    if (r)
	return r;
    if (su_get_port(dst) < su_get_port(src))
	return -1;
    if (su_get_port(dst) > su_get_port(src))
	return +1;
    return 0;
}

int su_copy_addr(sockaddr_union *dst, sockaddr_union *src)
{
    if (dst->sa.sa_family == src->sa.sa_family)
	switch (dst->sa.sa_family) {
#ifdef AF_UNIX
	case AF_UNIX:
	    strcpy(dst->sun.sun_path, src->sun.sun_path);
#ifdef WITH_SUN_LEN
	    dst->sun.sun_len = src->sun.sun_len;
#endif				/* WITH_SUN_LEN */
	    return 0;
#endif				/* AF_UNIX */
#ifdef AF_INET
	case AF_INET:
	    dst->sin.sin_addr.s_addr = src->sin.sin_addr.s_addr;
	    return 0;
#endif				/* AF_INET */
#ifdef AF_INET6
	case AF_INET6:
	    dst->sin6.sin6_addr.s6_addr32[0] = src->sin6.sin6_addr.s6_addr32[0];
	    dst->sin6.sin6_addr.s6_addr32[1] = src->sin6.sin6_addr.s6_addr32[1];
	    dst->sin6.sin6_addr.s6_addr32[2] = src->sin6.sin6_addr.s6_addr32[2];
	    dst->sin6.sin6_addr.s6_addr32[3] = src->sin6.sin6_addr.s6_addr32[3];
	    return 0;
#endif				/* AF_INET6 */
	}
#if defined(AF_INET) && defined(AF_INET6)
    if (dst->sa.sa_family == AF_INET && src->sa.sa_family == AF_INET6) {
	if (!IN6_IS_ADDR_V4MAPPED(&src->sin6.sin6_addr))
	    return -1;

	dst->sin.sin_addr.s_addr = src->sin6.sin6_addr.s6_addr32[3];
	return 0;
    }

    if (dst->sa.sa_family == AF_INET6 && src->sa.sa_family == AF_INET) {
	dst->sin6.sin6_addr.s6_addr32[0] = dst->sin6.sin6_addr.s6_addr32[1] = 0;
	dst->sin6.sin6_addr.s6_addr32[2] = htonl(0xFFFF);
	dst->sin6.sin6_addr.s6_addr32[3] = src->sin.sin_addr.s_addr;
	return 0;
    }
#endif				/* defined(AF_INET) && defined(AF_INET6) */

    return -1;
}

int service_to_port(uint16_t *p, char *service, int proto)
{
    int i;
    if (1 != sscanf(service, "%d", &i)) {
	struct servent *se;
	if ((se = getservbyname(service, proto == SOCK_STREAM ? "tcp" : "udp")))
	    *p = ntohs(se->s_port);
	return 0;
    }
    if (i & ~0xffff)
	return -1;
    *p = (uint16_t) i;
    return 0;
}

int have_inet6()
{
    static int result = 0;
#ifdef AF_INET6
    static int initialized = 0;
    if (!initialized) {
	int so = socket(AF_INET6, SOCK_STREAM, 0);
	if (so > -1) {
	    close(so);
	    result = -1;
	}
	initialized = -1;
    }
#endif				/* AF_INET6 */
    return result;
}

char *inet_wildcard()
{
    static char *wildcard;
    if (!wildcard)
	wildcard = have_inet6()? "::" : "0.0.0.0";
    return wildcard;
}

char *inet_any()
{
    static char *any;
    if (!any)
	any = have_inet6()? "::/0" : "0.0.0.0/0";
    return any;
}

socklen_t su_len(sockaddr_union *sa)
{
    switch (sa->sa.sa_family) {
#ifdef AF_UNIX
    case AF_UNIX:
	return (socklen_t) sizeof(struct sockaddr_un);
#endif				/* AF_UNIX */
#ifdef AF_INET
    case AF_INET:
	return (socklen_t) sizeof(struct sockaddr_in);
#endif				/* AF_INET */
#ifdef AF_INET6
    case AF_INET6:
	return (socklen_t) sizeof(struct sockaddr_in6);
#endif				/* AF_INET6 */
    }
    return (socklen_t) sizeof(struct sockaddr);
}

int su_socket(int domain, int type, int protocol)
{
    int s = socket(domain, type, protocol);
    if (s > -1) {
	fcntl(s, F_SETFL, O_NONBLOCK);
    }
    return s;
}

int su_bind(int s, sockaddr_union *sa)
{
    int one = 1;

    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *) &one, (socklen_t) sizeof(one));
    setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (char *) &one, (socklen_t) sizeof(one));
#if defined(IPPROTO_IPV6) && defined(IPV6_BINDV6ONLY)
    one = 0;
    setsockopt(s, IPPROTO_IPV6, IPV6_BINDV6ONLY, (char *) &one, (socklen_t) sizeof(one));
#endif

    return bind(s, &sa->sa, su_len(sa));
}


char *su_ntop(sockaddr_union *sa, char *dst, size_t cnt)
{
    switch (sa->sa.sa_family) {
#ifdef AF_UNIX
    case AF_UNIX:
	if (strlen(sa->sun.sun_path) >= (size_t) --cnt)
	    return NULL;
	strcpy(dst, sa->sun.sun_path);
	return dst;
#endif				/* AF_UNIX */
#ifdef AF_INET
    case AF_INET:
	{
	    char *a;
	    a = inet_ntoa(sa->sin.sin_addr);
	    if (strlen(a) >= (size_t) --cnt)
		return NULL;
	    strcpy(dst, a);
	    return dst;
	}
#endif				/* AF_INET */
#ifdef AF_INET6
    case AF_INET6:
	return (char *) inet_ntop(AF_INET6, &sa->sin6.sin6_addr, dst, (socklen_t) cnt);
#endif				/* AF_INET6 */
    }
    return NULL;
}

int su_pton_p(sockaddr_union *su, char *src, uint16_t port)
{
    size_t l = strlen(src);
    char *s = alloca(l + 1);
    strncpy(s, src, l + 1);
    char *t = s;
    if (*s == '[') {
	s++, t++, l--;
	while (*t && *t != ']')
	    t++, l--;
	if (*t) {
	    *t++ = 0;
	    if (*t == ':') {
		int u = atoi(++t);
		if (u > -1)
		    port = u;
	    }
	}
    } else if (strchr(s, '.')) {
	t = strchr(s, ':');
	if (t) {
	    *t++ = 0;
	    int u = atoi(t);
	    if (u > -1)
		port = u;
	}
    }
    if (su_pton(su, s))
	return -1;
    su_set_port(su, port);
    return 0;
}

int su_pton(sockaddr_union *su, char *src)
{
    struct hints {
	int family;
	size_t len;
	char *prefix;
    };

    struct hints hints[] = {
#ifdef AF_UNIX
	{ AF_UNIX, 5, "unix:", },
#endif				/* AF_UNIX */
#ifdef AF_INET
	{ AF_INET, 5, "inet:", },
#endif				/* AF_INET */
#ifdef AF_INET6
	{ AF_INET6, 6, "inet6:", },
#endif				/* AF_INET6 */
	{ AF_UNSPEC, 0, NULL, }
    };

    struct hints *h = hints;

    while (h->prefix && strncasecmp(src, h->prefix, h->len))
	h++;

    src += h->len;

    memset(su, 0, sizeof(sockaddr_union));

    if (!src) {
#ifdef AF_INET6
	su->sa.sa_family = AF_INET6;
#else				/* AF_INET6 */
	su->sa.sa_family = AF_INET;
#endif				/* AF_INET6 */
	return 0;
    }
#ifdef AF_UNIX
    if (h->family == AF_UNIX || (h->family == AF_UNSPEC && *src == '/')) {
	if (strlen(src) >= sizeof(su->sun.sun_path))
	    return -1;
	su->sa.sa_family = AF_UNIX;
	strcpy(su->sun.sun_path, src);
#ifdef WITH_SUN_LEN
	su->sun.sun_len = strlen(su->sun.sun_path) + 1;
#endif				/* WITH_SUN_LEN */
	return 0;
    }
#endif				/* AF_UNIX */

#ifdef AF_INET6
    if (h->family == AF_INET6 || (h->family == AF_UNSPEC && strchr(src, ':'))) {
	su->sa.sa_family = AF_INET6;
	if (1 == inet_pton(AF_INET6, src, &su->sin6.sin6_addr))
	    return 0;
    }
#endif				/* AF_INET6 */

#ifdef AF_INET
    su->sa.sa_family = AF_INET;
    if (INADDR_NONE != (su->sin.sin_addr.s_addr = inet_addr(src)))
	return 0;
#endif				/* AF_INET */

    return -1;
}

int su_addrinfo(char *address, char *port, int protocol, int family, int count, void *data, int (*func)(sockaddr_union *, void *))
{
    sockaddr_union su = { 0 };
    uint16_t p = 0;
#ifdef AF_INET6
    struct addrinfo *res;
#else				/* AF_INET6 */
#ifdef AF_INET
    struct hostent *he;
#endif				/* AF_INET */
#endif				/* AF_INET6 */

    if (port && (service_to_port(&p, port, protocol) < 0))
	return -1;

    if (!address)
	address = inet_wildcard();

    if (!su_pton(&su, address)) {
	su_set_port(&su, p);
	func(&su, data);
	return 0;
    }
#ifdef AF_INET6
    struct addrinfo hints = {.ai_flags = AI_PASSIVE,.ai_protocol = protocol,.ai_family = family };

    if (!getaddrinfo(address, NULL, &hints, &res)) {
	int i;
	struct addrinfo *r = res;
	for (i = 0; r && (!count || count > i); r = r->ai_next, i++) {
	    su_set_port((sockaddr_union *) r->ai_addr, p);
	    if (!func((sockaddr_union *) r->ai_addr, data))
		break;
	}
	freeaddrinfo(res);
	return 0;
    }
#else				/* AF_INET6 */
#ifdef AF_INET
    if (family == AF_INET && (he = gethostbyname(address))) {
	su.sa.sa_family = AF_INET;
	su_set_port(&su, p);
	if (he->h_addrtype == AF_INET) {
	    int i;
	    u_int **a = (u_int **) he->h_addr_list;
	    for (i = 0; *a && (!count || count > i); a++, i++) {
		su.sin.sin_addr.s_addr = **a;
		if (!(func(&su, data)))
		    break;
	    }
	    return 0;
	}
    }
#endif				/* AF_INET */
#endif				/* AF_INET6 */
    return -1;
}

int su_nameinfo(sockaddr_union *su, char *host, size_t hostlen, char *serv, size_t servlen, int flags)
{
    switch (su->sa.sa_family) {
#ifdef AF_UNIX
    case AF_UNIX:
	if (serv)
	    *serv = 0;
	if (host)
	    return (hostlen <= (size_t) snprintf(host, (size_t) hostlen, "%s", su->sun.sun_path));
	return !serv;
#endif				/* AF_UNIX */
#ifdef AF_INET
    case AF_INET:
#endif				/* AF_INET */
#ifdef AF_INET6
    case AF_INET6:
	return getnameinfo(&su->sa, su_len(su), host, (socklen_t) hostlen, serv, (socklen_t) servlen, flags);
#else				/* AF_INET6 */
#ifdef AF_INET
	if (serv) {
	    *serv = 0;
	    if (!(flags & NI_NUMERICSERV)) {
		struct servent *se = getservbyport(su_get_port(su), (flags & NI_DGRAM) ? "udp" : "tcp");
		if (se && (size_t) servlen <= (size_t) snprintf(serv, servlen, "%s", se->s_name))
		    return -1;
	    }
	    if (!*serv && (size_t) servlen <= (size_t) snprintf(serv, servlen, "%d", su_get_port(su)))
		return -1;
	}
	if (host) {
	    char *a = NULL;
	    if (!(flags & NI_NUMERICHOST)) {
		struct hostent *he = gethostbyaddr((char *) &(su->sin.sin_addr), sizeof(su->sin.sin_addr), AF_INET);
		if (he)
		    a = (char *) he->h_name;
	    }
	    if (!a && !(flags & NI_NAMEREQD))
		a = inet_ntoa(su->sin.sin_addr);
	    if (a)
		return ((size_t) hostlen <= (size_t) snprintf(host, hostlen, "%s", a));
	} else if (serv)
	    return 0;
#endif				/* AF_INET */
#endif				/* AF_INET6 */
    }
    return -1;
}

int su_ptoh(sockaddr_union *su, struct in6_addr *a)
{
    switch (su->sa.sa_family) {
#ifdef AF_INET
    case AF_INET:
	a->s6_addr32[0] = a->s6_addr32[1] = 0;
	a->s6_addr32[2] = 0x0000FFFF;
	a->s6_addr32[3] = ntohl(su->sin.sin_addr.s_addr);
	return 0;
#endif				/* AF_INET */
#ifdef AF_INET6
    case AF_INET6:
	v6_ntoh(a, &su->sin6.sin6_addr);
	return 0;
#endif				/* AF_INET6 */
    }
    return -1;
}

int su_htop(sockaddr_union *su, struct in6_addr *a, int sa_family)
{
    memset(su, 0, sizeof(sockaddr_union));
    su->sa.sa_family = sa_family;
    switch (sa_family) {
#ifdef AF_INET
    case AF_INET:
	if (a->s6_addr32[0] || a->s6_addr32[1] || a->s6_addr32[2] != 0x0000FFFF)
	    return -1;
	su->sin.sin_addr.s_addr = htonl(a->s6_addr32[3]);
	return 0;
#endif				/* AF_INET */
#ifdef AF_INET6
    case AF_INET6:
	v6_ntoh(&su->sin6.sin6_addr, a);
	return 0;
#endif				/* AF_INET6 */
    }
    return -1;
}

static uint32_t cidr2mask[] = {
    0x00000000,
    0x80000000, 0xc0000000, 0xe0000000, 0xf0000000,
    0xf8000000, 0xfc000000, 0xfe000000, 0xff000000,
    0xff800000, 0xffc00000, 0xffe00000, 0xfff00000,
    0xfff80000, 0xfffc0000, 0xfffe0000, 0xffff0000,
    0xffff8000, 0xffffc000, 0xffffe000, 0xfffff000,
    0xfffff800, 0xfffffc00, 0xfffffe00, 0xffffff00,
    0xffffff80, 0xffffffc0, 0xffffffe0, 0xfffffff0,
    0xfffffff8, 0xfffffffc, 0xfffffffe, 0xffffffff
};

int v6_common_cidr(struct in6_addr *a, struct in6_addr *b, int min)
{
    int m;
    for (m = 0; m < min && (v6_bitset(*a, m + 1) == v6_bitset(*b, m + 1)); m++);
    return m;
}

void v6_network(struct in6_addr *n, struct in6_addr *a, int m)
{
    for (int i = 0; i < 4; i++, m -= 32)
	n->s6_addr32[i] = a->s6_addr32[i] & cidr2mask[(m < 1) ? 0 : ((m > 32) ? 32 : m)];
}

void v6_broadcast(struct in6_addr *b, struct in6_addr *a, int m)
{
    for (int i = 0; i < 4; i++, m -= 32)
	b->s6_addr32[i] = a->s6_addr32[i] | ~cidr2mask[(m < 1) ? 0 : ((m > 32) ? 32 : m)];
}

int v6_cmp(struct in6_addr *a, struct in6_addr *b)
{
    for (int i = 0; i < 4; i++) {
	if (a->s6_addr32[i] < b->s6_addr32[i])
	    return -1;
	if (a->s6_addr32[i] > b->s6_addr32[i])
	    return +1;
    }
    return 0;
}

int v6_contains(struct in6_addr *n, int m, struct in6_addr *a)
{
    for (int i = 0; i < 4; i++, m -= 32)
	if (n->s6_addr32[i] != (a->s6_addr32[i] & cidr2mask[(m < 1) ? 0 : ((m > 32) ? 32 : m)]))
	    return 0;
    return -1;
}

void v6_ntoh(struct in6_addr *a, struct in6_addr *b)
{
    int i;
    for (i = 0; i < 4; i++)
	a->s6_addr32[i] = ntohl(b->s6_addr32[i]);
}

int v6_ptoh(struct in6_addr *a, int *cm, char *s)
{
    char *mask, *c = alloca(strlen(s) + 1);
    struct in6_addr m;
    int i, cmdummy;

    if (!cm)
	cm = &cmdummy;

    strcpy(c, s);

    mask = strchr(c, '/');
    if (mask)
	*mask++ = 0;

#ifdef AF_INET6
    if (strchr(c, ':')) {
	if (mask) {
	    if (strchr(mask, ':')) {
		if (1 != inet_pton(AF_INET6, c, &m))
		    return -1;
		v6_ntoh(&m, &m);
		for (*cm = 0; *cm < 128 && v6_bitset(m, *cm + 1); (*cm)++);
	    } else
		*cm = atoi(mask);
	} else
	    *cm = 128;

	if (1 != inet_pton(AF_INET6, c, a))
	    return -1;

	v6_ntoh(a, a);
	return 0;
    } else
#endif
    {
	if (mask) {
	    if (strchr(mask, '.')) {
		in_addr_t ia = inet_addr(mask);
		if (ia == INADDR_NONE)
		    return -1;
		for (i = 0; i < 3; i++)
		    m.s6_addr32[i] = 0;
		m.s6_addr32[3] = ntohl(ia);
		for (*cm = 96; *cm < 128 && v6_bitset(m, *cm + 1); (*cm)++);
	    } else
		*cm = atoi(mask) + 96;
	} else
	    *cm = 128;

	a->s6_addr32[0] = a->s6_addr32[1] = 0;
	a->s6_addr32[2] = 0x0000FFFF;
	a->s6_addr32[3] = ntohl(inet_addr(c));
	return a->s6_addr32[3] == INADDR_NONE;
    }
}

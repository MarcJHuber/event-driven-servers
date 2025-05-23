/*
 * io_dns_revmap.c
 * (C) 2002-2023 Marc Huber <Marc.Huber@web.de>
 *
 */

#include <stdio.h>
#include <string.h>
#include "misc/sysconf.h"
#include "misc/io_dns_revmap.h"
#include "misc/rb.h"
#include "misc/net.h"
#include "misc/memops.h"

#ifdef WITH_ARES
#include <ares.h>
#if ARES_VERSION < 0x11200	// private values until 1.18.0, see https://c-ares.org/changelog.html
#ifndef C_IN
#define C_IN 1
#endif
#ifndef T_PTR
#define T_PTR 12
#endif
#else
#include <ares_nameser.h>
#endif
#include <sys/uio.h>
#endif

struct io_dns_item {
    void *app_cb;
    void *app_ctx;
#ifdef WITH_ARES
    struct io_dns_ctx *idc;
    int canceled;
#endif
};

struct io_dns_ctx {
    struct io_context *io;
#ifdef WITH_ARES
    rb_tree_t *by_addr;
#endif
    rb_tree_t *by_app_ctx;
#ifdef WITH_ARES
    ares_channel channel;
#endif
#ifdef VRF_BINDTODEVICE
    char *vrf;
    size_t vrflen;
#endif
#if defined(VRF_RTABLE) || defined(VRF_SETFIB)
    unsigned intvrf;
#endif
};

#ifdef WITH_ARES
static int idi_cmp_addr(const void *v1, const void *v2)
{
    if (v1 < v2)
	return -1;
    if (v1 > v2)
	return +1;
    return 0;
}
#endif

static int idi_cmp_app_ctx(const void *v1, const void *v2)
{
    if (((struct io_dns_item *) v1)->app_ctx < ((struct io_dns_item *) v2)->app_ctx)
	return -1;
    if (((struct io_dns_item *) v1)->app_ctx > ((struct io_dns_item *) v2)->app_ctx)
	return +1;
    return 0;
}

#ifdef WITH_ARES
#if ARES_VERSION < 0x011c00
static void io_ares_set(struct io_dns_ctx *);
#endif

static void io_ares_read(struct io_dns_ctx *idc, int sock)
{
    ares_process_fd(idc->channel, sock, ARES_SOCKET_BAD);
#if ARES_VERSION < 0x011c00
    io_ares_set(idc);
#endif
}

static void io_ares_write(struct io_dns_ctx *idc, int sock)
{
    ares_process_fd(idc->channel, ARES_SOCKET_BAD, sock);
#if ARES_VERSION < 0x011c00
    io_ares_set(idc);
#endif
}

static void io_ares_readwrite(struct io_dns_ctx *idc, int sock)
{
    ares_process_fd(idc->channel, sock, sock);
#if ARES_VERSION < 0x011c00
    io_ares_set(idc);
#endif
}

#if ARES_VERSION < 0x011c00
static void io_ares_set(struct io_dns_ctx *idc)
{
    ares_socket_t socks[ARES_GETSOCK_MAXNUM];
    for (int i = 0; i < ARES_GETSOCK_MAXNUM; i++)
	socks[i] = ARES_SOCKET_BAD;
    int bits = ares_getsock(idc->channel, socks, ARES_GETSOCK_MAXNUM);
    for (int i = 0; i < ARES_GETSOCK_MAXNUM; i++) {
	int s = socks[i];
	if (s != ARES_SOCKET_BAD) {
	    if (ARES_GETSOCK_WRITABLE(bits, i))
		io_set_o(idc->io, s);
	    else
		io_clr_o(idc->io, s);
	    if (ARES_GETSOCK_READABLE(bits, i))
		io_set_i(idc->io, s);
	    else
		io_clr_i(idc->io, s);
	}
    }
}
#else
static void io_ares_state_cb(void *data, ares_socket_t socket_fd, int readable, int writable)
{
    if (writable)
	io_set_o(((struct io_dns_ctx *) data)->io, socket_fd);
    else
	io_clr_o(((struct io_dns_ctx *) data)->io, socket_fd);
    if (readable)
	io_set_i(((struct io_dns_ctx *) data)->io, socket_fd);
    else
	io_clr_i(((struct io_dns_ctx *) data)->io, socket_fd);
}
#endif
#endif

#ifdef WITH_ARES
static ares_socket_t asocket(int domain, int type, int protocol, void *opaque)
{
    struct io_dns_ctx *idc = (struct io_dns_ctx *) opaque;
    int fd = socket(domain, type, protocol);
#ifdef VRF_BINDTODEVICE
    if (idc->vrf)
	setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, idc->vrf, idc->vrflen);
#endif
#ifdef VRF_RTABLE
    if (idc->intvrf >= 0)
	setsockopt(fd, SOL_SOCKET, SO_RTABLE, (unsigned int *) &idc->intvrf, sizeof(idc->intvrf));
#endif
#ifdef VRF_SETFIB
    if (idc->intvrf >= 0)
	setsockopt(fd, SOL_SOCKET, SO_SETFIB, (unsigned int *) &idc->intvrf, sizeof(idc->intvrf));
#endif
    if (fd > -1) {
	io_register(idc->io, fd, idc);
	io_set_cb_i(idc->io, fd, (void *) io_ares_read);
	io_set_cb_o(idc->io, fd, (void *) io_ares_write);
	io_set_cb_h(idc->io, fd, (void *) io_ares_readwrite);
	io_set_cb_e(idc->io, fd, (void *) io_ares_readwrite);
    }
    return fd;
}

static int aclose(ares_socket_t fd, void *opaque)
{
    struct io_dns_ctx *idc = (struct io_dns_ctx *) opaque;
    return io_close(idc->io, fd);
}

#if ARES_VERSION < 0x012200
static int aconnect(ares_socket_t fd, const struct sockaddr *addr, ares_socklen_t addrlen, void *opaque __attribute__((unused)))
{
    return connect(fd, addr, addrlen);
}
#else
static int aconnect(ares_socket_t fd, const struct sockaddr *addr, ares_socklen_t addrlen, unsigned int flags __attribute__((unused)), void *opaque
		    __attribute__((unused)))
{
    return connect(fd, addr, addrlen);
}
#endif

static ares_ssize_t arecvfrom(ares_socket_t fd, void *buf, size_t len, int flags, struct sockaddr *src_addr, ares_socklen_t *addrlen, void *opaque
			      __attribute__((unused)))
{
    return recvfrom(fd, buf, len, flags, src_addr, addrlen);
}

#if ARES_VERSION < 0x012200
static ares_ssize_t asendv(ares_socket_t fd, const struct iovec *iov, int iovcnt, void *opaque __attribute__((unused)))
{
    return writev(fd, iov, iovcnt);
}
#else
static ares_ssize_t asendto(ares_socket_t sock, const void *buffer, size_t length,
			    int flags, const struct sockaddr *address, ares_socklen_t address_len, void *user_data __attribute__((unused)))
{
    return sendto(sock, buffer, length, flags, address, address_len);
}
#endif
#endif

struct io_dns_ctx *io_dns_init(struct io_context *io)
{
    struct io_dns_ctx *idc = Xcalloc(1, sizeof(struct io_dns_ctx));
#ifdef WITH_ARES
    struct ares_options options = {.flags = ARES_FLAG_STAYOPEN,.lookups = "b"
#if ARES_VERSION >= 0x011c00
	    ,.sock_state_cb = io_ares_state_cb,.sock_state_cb_data = idc
#endif
    };
    int res;
    idc->channel = calloc(1, sizeof(ares_channel));;
    res = ares_init_options(&idc->channel, &options, ARES_OPT_LOOKUPS
#if ARES_VERSION >= 0x011c00
			    | ARES_OPT_SOCK_STATE_CB
#endif
	);
    if (res == ARES_SUCCESS) {
#if ARES_VERSION < 0x012200
	static struct ares_socket_functions a_socket_functions;
	a_socket_functions.asocket = asocket;
	a_socket_functions.aclose = aclose;
	a_socket_functions.aconnect = aconnect;
	a_socket_functions.arecvfrom = arecvfrom;
	a_socket_functions.asendv = asendv;
	ares_set_socket_functions(idc->channel, &a_socket_functions, idc);
#else
	struct ares_socket_functions_ex a_socket_functions;
	a_socket_functions.asocket = asocket;
	a_socket_functions.aclose = aclose;
	a_socket_functions.aconnect = aconnect;
	a_socket_functions.arecvfrom = arecvfrom;
	a_socket_functions.asendto = asendto;
	ares_set_socket_functions_ex(idc->channel, &a_socket_functions, idc);
#endif
	idc->io = io;
	idc->by_addr = RB_tree_new(idi_cmp_addr, NULL);
	idc->by_app_ctx = RB_tree_new(idi_cmp_app_ctx, NULL);
#if ARES_VERSION < 0x011c00
	io_ares_set(idc);
#endif
    } else {
	free(idc->channel);
	free(idc);
	idc = NULL;
    }
#endif
    return idc;
}

void io_dns_cancel(struct io_dns_ctx *idc, void *app_ctx)
{
    struct io_dns_item i;
    rb_node_t *r;
    i.app_ctx = app_ctx;
    if ((r = RB_search(idc->by_app_ctx, &i))) {
#ifdef WITH_ARES
	struct io_dns_item *idi = RB_payload(r, struct io_dns_item *);
	idi->canceled = -1;

	// remove app_ctx here as the caller may reuse the memory
	RB_search_and_delete(idc->by_app_ctx, idi);
#endif
    }
}

void io_dns_destroy(struct io_dns_ctx *idc)
{
#ifdef WITH_ARES
    RB_tree_delete(idc->by_addr);
#endif
    RB_tree_delete(idc->by_app_ctx);
#ifdef WITH_ARES
    ares_destroy(idc->channel);
    idc->channel = NULL;
#endif
    free(idc);
}

void io_dns_add_addr(struct io_dns_ctx *idc, struct in6_addr *a, void *app_cb, void *app_ctx)
{
    if (idc) {
	sockaddr_union su = { 0 };

#ifdef AF_INET
	if (a->s6_addr32[0] == 0 && a->s6_addr32[1] == 0 && a->s6_addr32[2] == 0x0000FFFF) {
	    su.sin.sin_addr.s_addr = htonl(a->s6_addr32[3]);
	    su.sa.sa_family = AF_INET;
	}
#ifdef AF_INET6
	else
#endif
#endif
#ifdef AF_INET6
	{
	    v6_ntoh(&su.sin6.sin6_addr, a);
	    su.sa.sa_family = AF_INET6;
	}
#endif
	io_dns_add(idc, &su, app_cb, app_ctx);
    }
}

#ifdef WITH_ARES
#if ARES_VERSION < 0x011c00
static void a_callback(void *arg, int status, int timeouts, unsigned char *abuf, int alen);
#else
static void a_callback(void *arg, ares_status_t status, size_t timeouts, const ares_dns_record_t * dnsrec);
#endif

void io_dns_add(struct io_dns_ctx *idc, sockaddr_union *su, void *app_cb, void *app_ctx)
{
    char hex[] = "0123456789abcdef";
    char query[100];
    char *t = query;
    struct io_dns_item *idi = Xcalloc(1, sizeof(struct io_dns_item));

    switch (su->sa.sa_family) {
#ifdef AF_INET
    case AF_INET:
	snprintf(query, sizeof(query), "%u.%u.%u.%u.in-addr.arpa",
		 (su->sin.sin_addr.s_addr >> 24) & 0xff,
		 (su->sin.sin_addr.s_addr >> 16) & 0xff, (su->sin.sin_addr.s_addr >> 8) & 0xff, su->sin.sin_addr.s_addr & 0xff);
	break;
#endif				/* AF_INET */
#ifdef AF_INET6
    case AF_INET6:
	for (int i = 15; i > -1; i--) {
	    *t++ = hex[((char *) su->sin6.sin6_addr.s6_addr32)[i >> 2] & 0xf];
	    *t++ = '.';
	    *t++ = hex[((char *) su->sin6.sin6_addr.s6_addr32)[i >> 2] >> 4];
	    *t++ = '.';
	}
	strcpy(t, "IP6.ARPA");
#endif				/* AF_INET6 */
    }

    idi->idc = idc;
    idi->app_cb = app_cb;
    idi->app_ctx = app_ctx;
    RB_insert(idc->by_addr, idi);
    RB_insert(idc->by_app_ctx, idi);
#if ARES_VERSION < 0x011c00
    ares_query(idc->channel, query, C_IN, T_PTR, a_callback, idi);
    io_ares_set(idc);
#else
    ares_query_dnsrec(idc->channel, query, ARES_CLASS_IN, ARES_REC_TYPE_PTR, a_callback, idi, NULL);;
#endif
}
#endif

#ifdef WITH_ARES
#include <ctype.h>
#if ARES_VERSION < 0x011c00
static void a_callback(void *arg, int status, int timeouts __attribute__((unused)), unsigned char *abuf, int alen)
{
    struct io_dns_item *idi = (struct io_dns_item *) arg;

    if (!idi->canceled) {
	char *res = NULL;
	struct hostent *host = NULL;
	int ttl = -1;
	if (status == ARES_SUCCESS) {
	    status = ares_parse_ptr_reply(abuf, alen, NULL, 0, AF_INET, &host);
	    if (status == ARES_SUCCESS && host) {
		res = host->h_name;
		abuf += 12;
		alen -= 12;
		while (alen > 0 && *abuf) {
		    alen -= *abuf;
		    abuf += *abuf + 1;
		}
		abuf += 4;
		alen -= 4;
		if (alen > 10 && abuf[0] == 1 && (abuf[1] & 0xc0) == 0xc0 && abuf[3] == 0 && abuf[4] == 0x0c && abuf[5] == 0 && abuf[6] == 1)
		    ttl = (abuf[7] << 24) | (abuf[8] << 16) | (abuf[9] << 8) | abuf[10];
	    }
	}
	((void (*)(void *, char *, int)) idi->app_cb) (idi->app_ctx, res, ttl);
	if (host)
	    ares_free_hostent(host);
    }
    RB_search_and_delete(idi->idc->by_app_ctx, idi);
    RB_search_and_delete(idi->idc->by_addr, idi);
    free(idi);
}
#else
static void a_callback(void *arg, ares_status_t status, size_t timeouts __attribute__((unused)), const ares_dns_record_t *dnsrec)
{
    struct io_dns_item *idi = (struct io_dns_item *) arg;
    int ttl = -1;
    const char *res = NULL;

    if (!idi->canceled) {
	if (status == ARES_SUCCESS && ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_ANSWER) > 0) {
	    ares_dns_rr_t *rr = ares_dns_record_rr_get((ares_dns_record_t *) dnsrec, ARES_SECTION_ANSWER, 0);
	    res = ares_dns_rr_get_str(rr, ARES_RR_PTR_DNAME);
	    ttl = ares_dns_rr_get_ttl(rr);
	}
	((void (*)(void *, char *, int)) idi->app_cb) (idi->app_ctx, (char *) res, ttl);
    }
    RB_search_and_delete(idi->idc->by_app_ctx, idi);
    RB_search_and_delete(idi->idc->by_addr, idi);
    free(idi);
}
#endif
#endif

#ifdef WITH_ARES
int io_dns_set_servers(struct io_dns_ctx *idc, char *servers)
{
    return ares_set_servers_ports_csv(idc->channel, servers);
}
#endif

void io_dns_set_vrf(struct io_dns_ctx *idc __attribute__((unused)), char *vrf __attribute__((unused)))
{
#ifdef VRF_BINDTODEVICE
    if (idc->vrf)
	free(idc->vrf);
    idc->vrf = vrf;
    idc->vrflen = strlen(vrf) + 1;
#endif
#if defined(VRF_RTABLE) || defined(VRF_SETFIB)
    idc->intvrf = (unsigned) atoi(vrf);
#endif
}

#if 0
static void testcb(void *ctx __attribute__((unused)), char *hostname)
{
    fprintf(stderr, "%s\n", hostname);
    exit(0);
}

int main(int argc, char **argv)
{
    struct io_context *io = io_init();
    struct io_dns_ctx *idc;
    sockaddr_union su;

    su_pton(&su, argv[1]);

    idc = io_dns_init(io);

    io_dns_add(idc, &su, testcb, &su);
    io_main(io);
}
#endif

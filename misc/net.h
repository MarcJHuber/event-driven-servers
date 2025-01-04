/*
 * net.h
 * (C)1999-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id: net.h,v 1.22 2011/08/20 14:04:40 marc Exp marc $
 *
 */

#ifndef __NET_H_
#define __NET_H_
#include <sys/types.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netdb.h>

#include "misc/sysconf.h"
#undef sun

typedef union {
    struct sockaddr sa;
#ifdef AF_UNIX
    struct sockaddr_un sun;
#endif				/* AF_UNIX */
#ifdef AF_INET
    struct sockaddr_in sin;
#endif				/* AF_INET */
#ifdef AF_INET6
    struct sockaddr_in6 sin6;
#endif				/* AF_INET6 */
} sockaddr_union;

/*
 * int su_convert (sockaddr_union *su, u_int af);
 *
 * Converts su to address family af. Returns 0 on success, != 0 on error.
 */
int su_convert(sockaddr_union *, u_int);

/*
 * int su_copy_addr (sockaddr_union *to, sockaddr_union *from);
 *
 * Copies addresses. Returns 0 on success, != 0 on error.
 *
 */
int su_copy_addr(sockaddr_union *, sockaddr_union *);

/*
 * int su_equal (sockaddr_union *su1, sockaddr_union *su2);
 *
 * returns 0 if addresses and ports are equal, != 0 else.
 *
 */
int su_equal(sockaddr_union *, sockaddr_union *);

/*
 * int su_equal_addr (sockaddr_union *su1, sockaddr_union *su2);
 *
 * returns 0 if the addresses are equal, != 0 else.
 *
 */
int su_equal_addr(sockaddr_union *, sockaddr_union *);

/*
 * int su_cmp (sockaddr_union *su1, sockaddr_union *su2);
 *
 * returns -1/0/+1 if address and port of su1 </=/> su2
 *
 */
int su_cmp(sockaddr_union *, sockaddr_union *);

/*
 * int su_cmp_addr (sockaddr_union *su1, sockaddr_union *su2);
 *
 * returns -1/0/+1 if address of su1 </=/> su2
 *
 */
int su_cmp_addr(sockaddr_union *, sockaddr_union *);

/*
 * int su_get_port(sockaddr_union *su)
 * returns the port number, depending on the address family.
 *
 * int su_set_port(sockaddr_union *su, port)
 * sets the port number, depending on the address family.
 * Return value is 0 on success, != 0 on error.
 *
 */
uint16_t su_get_port(sockaddr_union *);
int su_set_port(sockaddr_union *, uint16_t);

/*
 * size_t su_len (sockaddr_union *su)
 *
 * Returns the length of the sockaddr structure, depending on the
 * address family.
 *
 */
socklen_t su_len(sockaddr_union *);

/*
 * int su_ntop (sockaddr_union * su, char *buf, size_t buflen)
 *
 * su_ntop converts the address portion of su to ASCII, storing it
 * in buf. 0 is returned on success, != 0 on error.
 *
 */
char *su_ntop(sockaddr_union *, char *, size_t);

/*
 * int su_pton (sockaddr_union *su, char *address);
 * int su_pton_p (sockaddr_union *, char *address, int port);
 *
 * su_pton converts address to a sockaddr_union structure.
 * su_pton_p is similar to su_pton, but accepts port as an additional
 * argument.
 * Both routines return 0 on success, -1 on error.
 *
 * Example:
 *
 * sockaddr_union su;
 * int res = su_pton_p (&su, "127.0.0.1", 8000);
 *
 */
int su_pton(sockaddr_union *, char *);
int su_pton_p(sockaddr_union *, char *, uint16_t);

/*
 * int have_inet6 ()
 *
 * returns -1 if IPv6 is supported by the host system, 0 else
 *
 */
int have_inet6(void);

/*
 * int inet_wildcard ()
 *
 * returns the IPv6 wildcard if available, IPv4 else.
 *
 */
char *inet_wildcard(void);

/*
 * int inet_any ()
 *
 * returns inet_wildcard() with "/0" appended.
 *
 */
char *inet_any(void);

/*
 * int service_to_port (uint16_t *port, char *service, int proto)
 *
 * If service is numeric it is converted to an integer and returned.
 * Else, service is looked up using getservent(). proto has to be either
 * SOCK_STREAM or SOCK_DGRAM.
 * -1 is returned on error.
 *
 * Example:
 *
 * int res = service_to_port (&ftp_port, "ftp", SOCK_STREAM);
 *
 */
int service_to_port(uint16_t *, char *, int);

/*
 * int su_addrinfo (char *address,
 * 		    char *port,
 *		    int protocol,
 *		    int family,
 *		    int count,
 *		    void *data,
 *		    int (*func) (sockaddr_union *, void *))
 *
 * su_addrinfo() first generates a list of sockaddr structures:
 *   - If address is a hostname, the list consists of IPv4 or IPv6 addresses,
 *     The list may be limited to a particular address family by setting the
 *     family parameter to PF_INET of PF_INET6. Use PF_UNSPEC for arbitrary
 *     protocols. If count is non-zero, the list is limited to count entries.
 *   - If address is a IPv4 or IPv6 address, the list consists of that single
 *     address.
 *   - If address starts with a '/' character, AF_UNIX is assumed, and the
 *     list consists of this single address.
 *
 * port may be either numerical or a service name. The protocol to use
 * is determined by the protocol parameter (SOCK_DGRAM or SOCK_STREAM).
 *
 * func() is called for up to count sockaddr of the previously generated
 * list (or for all, if count is 0. If func() returns non-zero for a
 * sockaddr, the remaining sockaddr structs are skipped.
 * The second argument to func() is the data parameter.
 *
 * Example:
 *
 * struct socket_info
 * {
 *   int use_ssl;
 * };
 * ...
 * int cb (sockaddr_union *sa, void *data)
 * {
 *   int s = socket (sa->sa.sa_family, SOCK_STREAM, 0);
 *   ...
 *   if (((struct socket_info *) data)->use_ssl)
 *   {
 *     ...
 *   }
 *   return 0;
 * }
 *
 * int main ()
 * {
 *   struct socket_info si;
 *   ...
 *   si.use_ssl = 0;
 *   ...
 *   su_addrinfo ("127.0.0.1", "ftp", SOCK_STREAM, PF_INET, 0, &si, cb);
 *   ...
 * }
 *
 */
int su_addrinfo(char *, char *, int, int, int, void *, int (*)(sockaddr_union *, void *));


/*
 * int su_nameinfo (sockaddr_union *su,
 *		    char *host,
 *		    size_t hostlen,
 *		    char *serv,
 *		    size_t servlen,
 *		    int flags);
 *
 * Just like getnameinfo(3), this function is designed for
 * protocol-independant address-to-nodename translation.
 *
 */

#ifndef NI_NUMERICHOST
#define NI_NUMERICHOST	1	/* Don't try to look up hostname.  */
#define NI_NUMERICSERV	2	/* Don't convert port number to name.  */
#define NI_NOFQDN	4	/* Only return nodename portion.  */
#define NI_NAMEREQD	8	/* Don't return numeric addresses.  */
#define NI_DGRAM	16	/* Look up UDP service rather than TCP.  */
#endif				/* NI_NUMERICHOST */

int su_nameinfo(sockaddr_union *, char *, size_t, char *, size_t, int);

int su_bind(int, sockaddr_union *);
int su_socket(int, int, int);

#define su_connect(A,B) connect(A,B.sa,su_len(B))

/* IPv6 handling */

#ifndef AF_INET6
struct in6_addr {
    unsigned int s6_addr32[4];
};
#endif

#define v6_bitset(a,b) ((b > 0) && ((b) < 129) && \
        ((a).s6_addr32[(b-1)>>5] & (0x80000000 >> ((b-1)&0x1f))))

/* extract IP address (in host byte order) from sockaddr_union */
int su_ptoh(sockaddr_union *, struct in6_addr *);

/* copy IP address (in host byte order) to sockaddr_union */
int su_htop(sockaddr_union *, struct in6_addr *, int af_family);

/* return CIDR size of smalles supernet */
int v6_common_cidr(struct in6_addr *, struct in6_addr *, int);

/* clear host bits */
void v6_network(struct in6_addr *, struct in6_addr *, int);

/* set host bits */
void v6_broadcast(struct in6_addr *, struct in6_addr *, int);

/* return -1 if first address < second address, +1 if >, 0 if equal*/
int v6_cmp(struct in6_addr *, struct in6_addr *);

/* first address := ntoh(second address) */
void v6_ntoh(struct in6_addr *, struct in6_addr *);

/* Does first address/mask contain second address? */
int v6_contains(struct in6_addr *, int, struct in6_addr *);

/* parse input CIDR string, set address and mask */
int v6_ptoh(struct in6_addr *, int *, char *);
#endif				/* __NET_H_ */

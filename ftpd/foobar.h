/* foobar.h (C)1999-2011 by Marc Huber <Marc.Huber@web.de>
 *
 * $Id: foobar.h,v 1.6 2011/02/27 12:22:16 marc Exp $
 *
 */

#ifndef __FOOBAR_H_
#define __FOOBAR_H_

int rfc959_eval(sockaddr_union *, char *);
char *rfc959_str(sockaddr_union *, char *, size_t);

int foobar2af(int);
int af2foobar(int);
int foobar_eval(sockaddr_union *, char *);
char *foobar_str(sockaddr_union *, char *, size_t);
char *print_foobar_families(char *, size_t);

int rfc2428_2_af(int);
int af2rfc2428(int);
int rfc2428_eval(sockaddr_union *, char *);
char *rfc2428_str(sockaddr_union *, char *, size_t);
char *print_rfc2428_families(char *, size_t);

#endif				/* __FOOBAR_H_ */

/* ssl_init.h (C)1999,2000 by Marc Huber <Marc.Huber@web.de>
 *
 * $Id: ssl_init.h,v 1.3 2005/12/31 12:14:23 huber Exp $
 *
 */

#ifndef __SSL_INIT_H__
#define __SSL_INIT_H__
#include <openssl/ssl.h>
SSL_CTX *ssl_init(char *, char *, char *, char *);
SSL_CTX *ssl_init_verify(SSL_CTX *, int, char *, char *);
void ssl_set_verify(SSL_CTX *, void *);
#endif				/* __SSL_INIT_H__ */

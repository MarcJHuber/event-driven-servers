/*
 * headers.h (C)1999-2011 by Marc Huber <Marc.Huber@web.de>
 *
 *
 * $Id: headers.h,v 1.14 2011/08/06 20:28:33 marc Exp marc $
 *
 */

#include "misc/sysconf.h"
#include "mavis/debug.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <limits.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
//#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <utime.h>
#include <time.h>
#include <stdlib.h>
#include <stdarg.h>
#include <syslog.h>
#include <signal.h>
#include <ctype.h>
#include <sysexits.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/poll.h>

#include "misc/setproctitle.h"
#include "mavis/set_proctitle.h"
#include "misc/net.h"
#include "misc/memops.h"
#include "mavis/log.h"
#include "misc/io_sched.h"
#include "misc/strops.h"
#include "mavis/mavis.h"

#define TMPBUFSIZE 2 * PATH_MAX

#ifdef __MAIN__
#define WHERE
#define INITVAL(x) = x
#else
#define WHERE extern
#define INITVAL(x)
#endif

#ifdef WITH_TLS
 #include <tls.h>
  WHERE struct tls *ssl_ctx INITVAL(NULL);
#else
 #ifdef WITH_SSL
  #include <openssl/ssl.h>
  #include <openssl/err.h>
  #include <openssl/bio.h>
  #include <openssl/pem.h>

  WHERE SSL_CTX *ssl_ctx INITVAL(NULL);
#endif
#endif				/* WITH_SSL */
WHERE char *ssl_cert INITVAL(NULL);
WHERE char *ssl_key INITVAL(NULL);
WHERE char *ssl_pass INITVAL(NULL);

WHERE int die_when_idle INITVAL(0);
WHERE char *conffile INITVAL(NULL);
WHERE u_long conntimeout INITVAL(0);
WHERE u_long id_max INITVAL(0);
WHERE int nfds_max;
WHERE struct timeval now;
WHERE struct context *ctx_spawnd INITVAL(NULL);

#define BUFSIZE 16000
#include "misc/buffer.h"

struct context;

void parse_decls(struct sym *);
void setup_signals(void);
void process_signals(void);
int setup_socket(sockaddr_union *, u_int);
void logerr(char *, ...) __attribute__((format(printf, 1, 2)));
void logmsg(char *, ...) __attribute__((format(printf, 1, 2)));
void cleanup(struct context *, int);
void cleanup_error(struct context *, int);
void cleanup_one(struct context *, int);
void cleanup_spawnd(struct context *, int);

struct buffer *write2buffer(struct buffer *, char *, int);

void connected(struct context *, int);
void connect_out(struct context *, int);
void accepted(struct context *, int);
void accept_in(struct context *, int);
void buffer2socket(struct context *, int);
void socket2buffer(struct context *, int);
void socket2control(struct context *, int);
void control2socket(struct context *, int);
void invalid_infn(struct context *, int);
void invalid_outfn(struct context *, int);
void newconnect(struct context *, int);
void accepted_raw(int, struct scm_data_accept *);

#undef MIN
#define MIN(A,B) ((A) < (B) ? (A) : (B))

struct connect_address_s {
    sockaddr_union sa;
    int sock;
    int protocol;
    u_int dead;
    u_int weight;		/* current_connects/weight == current_priority */
    u_int use;
};

WHERE int con_arr_len INITVAL(0);

WHERE struct connect_address_s *con_arr INITVAL(NULL);
WHERE sockaddr_union *lcladdr INITVAL(NULL);
WHERE int rebalance INITVAL(0);

struct context *new_context(struct io_context *);

/* shortcuts ... */
#define SC (struct context *)

struct context {
    struct io_context *io;
    struct buffer *bufi;
    struct buffer *bufo;
    int ifn;
    int ofn;
    struct timeval tv;
    int con_arr_idx;
    u_int listener:1;
    u_int failed:1;
    u_int is_client:1;
#ifdef WITH_TLS
    struct tls *ssl;
#else
#ifdef WITH_SSL
    SSL *ssl;
#endif				/* WITH_SSL */
#endif				/* WITH_SSL */
};

/*
 * headers.h (C)1998-2011 by Marc Huber <Marc.Huber@web.de>
 *
 * $Id: headers.h,v 1.11 2011/07/17 19:12:19 marc Exp $
 *
 */

#include "misc/sysconf.h"
#include <limits.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <utime.h>
#include <time.h>
#include <stdlib.h>
#include <stdarg.h>
#include <pwd.h>
#include <grp.h>
#include <syslog.h>
#include <signal.h>
#include <ctype.h>
#include <sys/time.h>
#include "mavis/debug.h"
#include "mavis/log.h"
#include "misc/strops.h"
#include "misc/io_sched.h"
#include "misc/net.h"
#include "mavis/blowfish.h"
#include "mavis/mavis.h"
#include "misc/setproctitle.h"

#include <sys/poll.h>

#ifdef __MAIN__
#define WHERE
#define INITVAL(x) = x
#else
#define WHERE extern
#define INITVAL(x)
#endif

WHERE char *pidfile INITVAL(NULL);
WHERE int background INITVAL(0);
WHERE int mavis_timeout INITVAL(3);
WHERE int mavis_retries INITVAL(5);
WHERE u_long stat_period INITVAL(0);
WHERE int transmit_password INITVAL(0);
WHERE struct io_context *io INITVAL(NULL);
WHERE mavis_ctx *mcx INITVAL(NULL);

/* shortcuts ... */
#define SC (struct context *)

struct context {
    struct io_context *io;
    int sock;
    sockaddr_union sa;
    struct blowfish_ctx *blowfish;
    uid_t uid;
    gid_t gid;
    mode_t mode;
};

void udp_error(struct context *, int);
void client_io(struct context *, int);
struct context *new_context(struct io_context *);
void setup_signals(void);
void parse_decls(struct sym *);
int acl_check(sockaddr_union *);

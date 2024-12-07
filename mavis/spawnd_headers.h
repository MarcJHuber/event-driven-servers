/*
 * headers.h
 *
 * (C)2000-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id: spawnd_headers.h,v 1.35 2020/01/18 12:57:44 marc Exp marc $
 *
 */

#include "misc/sysconf.h"
#include "mavis/debug.h"
#include <limits.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
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
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <setjmp.h>

#include "mavis/mavis.h"
#include "misc/net.h"
#include "misc/strops.h"
#include "misc/memops.h"
#include "mavis/log.h"
#include "misc/io_sched.h"
#include "misc/setproctitle.h"
#include "mavis/set_proctitle.h"

#define LOGPRIO LOG_INFO

#define LOG_NONE 0

extern struct spawnd_data spawnd_data;

struct spawnd_data {
    char *conffile;
    char *child_id;
    char *child_config;
    char *child_path;
    uid_t uid;
    gid_t gid;
    char *cwd;			/* child's working directory */
    int inetd;
    int abandon;
    int background;
    int background_lock;
    char *pidfile;
    int pidfile_lock;
    int listeners_max;
    int listeners_inactive;
    enum token overload;
    char *overload_hint;
    struct spawnd_context **listener_arr;
    struct spawnd_context **server_arr;
    time_t tracking_period;
    int tracking_size;
    int retry_delay;
    int bind_failures;
    int keepcnt;
    int keepidle;
    int keepintvl;
    int scm_bufsize;
};

struct spawnd_context {
    struct io_context *io;
    int fn;
    u_int is_listener:1;	/* 0: server, 1: listener */
    u_int use_ssl:1;		/* listener only */
    u_int dying:1;		/* server only */
    u_int logged_retry:1;	/* server only */
    u_int haproxy:1;		/* server only */
    int socktype;		/* SOCK_STREAM, SOCK_SEQPACKET */
    int protocol;		/* IPROTO_IP (default)/_TCP/_SCTP */
    short port;			/* tcp/udp port in network byte order */
    int listen_backlog;
    int overload_backlog;
    struct timeval tv;		/* server only */
    int use;			/* server only */
    pid_t pid;			/* server only */
    char tag[SCM_REALM_SIZE + 1];	/* listener only */
    ssize_t tag_len;		/* listener only */
#ifdef VRF_BINDTODEVICE
    char *vrf;			/* server only */
    ssize_t vrf_len;		/* server only */
#endif
#if defined(VRF_RTABLE) || defined(VRF_SETFIB)
    int vrf_id;
#endif
    uid_t uid;
    gid_t gid;
    mode_t mode;
    int retry_delay;
    int keepcnt;
    int keepidle;
    int keepintvl;
    sockaddr_union sa;
};

void get_exec_path(char **, char *);
void spawnd_setup_signals(void);
void spawnd_process_signals(void);
int spawnd_spawn_child(pid_t *);
int spawnd_note_listener(sockaddr_union *, void *);
void spawnd_parse_decls(struct sym *);
int spawnd_send_msg(int, char *, int);
int spawnd_recv_msg(int, char **, int *);
void spawnd_add_child(void);
void spawnd_del_child(int);
void spawnd_accepted(struct spawnd_context *, int);
void spawnd_bind_listener(struct spawnd_context *, int);
int spawnd_acl_check(sockaddr_union *);
void spawnd_cleanup_internal(struct spawnd_context *, int);
void spawnd_cleanup_tracking(void);
struct spawnd_context *spawnd_new_context(struct io_context *);
void spawnd_adjust_tracking(int, int);

/*
 * headers.h
 * (C)1997-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id: headers.h,v 1.33 2020/12/06 19:31:31 marc Exp marc $
 *
 */

#ifndef __HEADERS_H_
#define __HEADERS_H_

#include "misc/sysconf.h"

#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <limits.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <utime.h>
#include <time.h>
#include <stdlib.h>
#include <signal.h>
#include <ctype.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sysexits.h>
#include <setjmp.h>

#include "misc/sysconf.h"
#include "misc/strops.h"
#include "mavis/mavis.h"
#include "misc/memops.h"
#include "mavis/debug.h"
#include "mavis/log.h"
#include "misc/memops.h"
#include "misc/io.h"
#include "misc/rb.h"
#include "misc/io_sched.h"
#include "misc/io_child.h"

#ifdef WITH_ZLIB
#include <zlib.h>
#endif

#ifdef WITH_DNS
#include "misc/io_dns_revmap.h"
#endif

#ifdef WITH_PCRE
#include <pcre.h>
#endif

#ifdef WITH_PCRE2
#include <pcre2.h>
#endif

#include <regex.h>

#include "messages.h"
#include "misc/net.h"
#include "mavis/set_proctitle.h"
#include "misc/setproctitle.h"

#ifdef __MAIN__
#define WHERE
#define INITVAL(x) = x
#else
#define WHERE extern
#define INITVAL(x)
#endif				/* __MAIN__ */

#ifdef WITH_SSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

WHERE SSL_CTX *ssl_ctx INITVAL(NULL);
WHERE char *ssl_cert INITVAL(NULL);
WHERE char *ssl_key INITVAL(NULL);
WHERE char *ssl_pass INITVAL(NULL);
WHERE char *ssl_ciphers INITVAL(NULL);
WHERE int ssl_auth INITVAL(0);
WHERE int ssl_auth_req INITVAL(0);
WHERE int ssl_old_draft INITVAL(0);
WHERE int ssl_depth INITVAL(5);
WHERE char *ssl_cafile INITVAL(NULL);
WHERE char *ssl_capath INITVAL(NULL);
#endif				/* WITH_SSL */

#include "misc/mymd5.h"

#include "misc/crc32.h"
#include "foobar.h"
#include "defaults.h"

#define TMPBUFSIZE 2 * PATH_MAX
#define MAXBUFSIZE1413	1000

#define LOG_NONE	0
#define LOG_COMMAND	1
#define LOG_TRANSFER	2
#define LOG_EVENT	4
#define LOG_IDENT	8
#define LOG_OVERRIDE	16

#ifdef WITH_DNS
WHERE struct io_dns_ctx *idc INITVAL(NULL);
#endif

WHERE uid_t current_uid INITVAL(0);
WHERE gid_t current_gid INITVAL(0);
WHERE uid_t real_uid INITVAL(0);
WHERE gid_t real_gid INITVAL(0);
WHERE int update_ids INITVAL(0);
WHERE char *logformat_transfer INITVAL(NULL);
WHERE char *logformat_command INITVAL(NULL);
WHERE char *logformat_event INITVAL(NULL);
WHERE char logformat_delimiter INITVAL('|');
WHERE char logformat_substitute INITVAL('_');
WHERE int die_when_idle INITVAL(0);
WHERE int nlst_files_only INITVAL(0);
WHERE int hide_version INITVAL(0);
WHERE u_long id_max INITVAL(0);
WHERE mavis_ctx *mcx INITVAL(NULL);
WHERE int sigbus_cur INITVAL(-1);
WHERE jmp_buf sigbus_jmpbuf;
WHERE struct context *ctx_spawnd INITVAL(NULL);
WHERE struct io_context *io INITVAL(NULL);
WHERE int nfds_max;

#define BUFSIZE			32768
WHERE size_t bufsize INITVAL(BUFSIZE);

#ifdef WITH_MMAP
#ifdef _LP64
#define BUFSIZE_MMAP		0
#else
#define BUFSIZE_MMAP		262144
#endif
WHERE int use_mmap INITVAL(-1);
WHERE int pagesize;
WHERE size_t bufsize_mmap INITVAL(BUFSIZE_MMAP);
#endif				/* WITH_MMAP */

#ifdef WITH_SENDFILE
WHERE int use_sendfile INITVAL(-1);
#endif				/* WITH_SENDFILE */

struct acl_rule;

struct acl_set {
    //char *name;                       /* name of referred access list */
    struct ftp_acl *acl;	/* pointer to access list */
    u_int log:1;		/* log command */
    u_int negate:1;		/* negate result */
    u_int permit:1;		/* permit on match (commands only) */
    struct acl_set *next;	/* pointer to next acl_set */
};

WHERE struct acl_set **requests_aclset INITVAL(NULL);
WHERE struct acl_set **requests_site_aclset INITVAL(NULL);

struct context;

struct md_method {
    char *ftp_name;
    char *openssl_name;
#ifdef WITH_SSL
    const EVP_MD *md;
#endif
    void (*init)(struct context *);
    void (*update)(struct context *, u_char *, size_t);
    char *(*final)(struct context *);

    struct md_method *next;
};

WHERE struct md_method *md_methods INITVAL(NULL);
struct md_method *md_method_find(struct md_method *, char *);
void md_init(void);

int acl_add(char *, char *, char *, char *, char *, char *);
void acl_calc(struct context *);
void acl_init(void);
void acl_finish(void);
void acl_conf_readme(struct context *);
int acl_binary_only(struct context *, char *, char *);
int acl_compression(struct context *, char *, char *);
int acl_checksum(struct context *, char *, char *);
void acl_set_umask(struct context *, char *, char *);
void acl_set_deflate_level(struct context *);
void acl_check(struct context *, struct acl_rule *, char *, char *);
enum token eval_ftp_acl(struct context *, struct ftp_acl *, char *, char *);


void read_mimetypes(char *);

#define SYMLINKS_NO	0x0
#define SYMLINKS_YES	0x1
#define SYMLINKS_ROOT	0x2
#define SYMLINKS_SAME	0x4
#define SYMLINKS_REAL	0x8

#undef MIN
#define MIN(A,B) (((A) < (B)) ? (A) : (B))

#include "misc/buffer.h"

int conf(int, char **);
void file2control(struct context *, char *, char *);
void set_maxfd(int);
void clr_maxfd(int);
void setup_signals(void);
void process_signals(void);
int setup_socket(sockaddr_union *, u_int);
void setup_invalid_callbacks(struct io_context *);

void ftp_log(struct context *, uint, char *);

void parse_decls(struct sym *);

void checkcmd(struct context *, char *);
void reply(struct context *, char *);
void replyf(struct context *, char *, ...)
    __attribute__((format(printf, 2, 3)));
struct buffer *buffer_reply(struct buffer *, char *, size_t);

char *parsepath(struct context *, char *);
char *buildpath(struct context *, char *);

int check_incoming(struct context *, char *, u_int);

char *lookup_uid(struct context *, uid_t);
char *lookup_gid(struct context *, gid_t);

void auth_mavis(struct context *, char *);
void readcmd(struct context *, int);
void cleanup(struct context *, int);
void cleanup_data(struct context *, int);
void cleanup_data_reuse(struct context *, int);
void cleanup_control(struct context *, int);
void cleanup_data_ssl_error(struct context *, int);
void cleanup_control_ssl_error(struct context *, int);
void cleanup_ident(struct context *, int);
void cleanup_spawnd(struct context *, int);
int cleanup_file(struct context *, int);

void ident_init(void);
void ident_out(struct context *);

void message_init(void);
char *cook(struct context *cur, char *, char *, char *, int);

void catchhup(int);

void setup_sig_bus(void);

int chunk_get(struct context *, off_t *);
int chunk_release(struct context *, off_t);

#define chunk_remaining(A) (A->remaining || A->dbufi)

void quota_add(struct context *, long long);

#if defined(WITH_PCRE) || defined(WITH_PCRE2)
int PCRE_add(char *, char *, char *);
int PCRE_exec(const char *, char *, size_t);
#endif

int convstat(struct context *, struct stat *, char *);
int pickystat(struct context *, struct stat *, char *);
int pickystat_path(struct context *, struct stat *, char *);

void h_site_idle(struct context *, char *);
void h_site_checkmethod(struct context *, char *);
void h_hash(struct context *, char *);
void h_site_checksum(struct context *, char *);
void h_site_chmod(struct context *, char *);
void h_site_help(struct context *, char *);
void h_site_id(struct context *, char *);
void h_site_groups(struct context *, char *);
void h_site_group(struct context *, char *);
void h_site_umask(struct context *, char *);

void h_mdtm(struct context *, char *);
void h_size(struct context *, char *);
void h_port(struct context *, char *);
void h_pasv(struct context *, char *);
void h_list(struct context *, char *);
void h_nlst(struct context *, char *);
void h_user(struct context *, char *);
void h_pass(struct context *, char *);
void h_cdup(struct context *, char *);
void h_rein(struct context *, char *);
void h_quit(struct context *, char *);
void h_type(struct context *, char *);
void h_mode(struct context *, char *);
void h_retr(struct context *, char *);
void h_dele(struct context *, char *);
void h_mkd(struct context *, char *);
void h_rmd(struct context *, char *);
void h_rnfr(struct context *, char *);
void h_rnto(struct context *, char *);
void h_appe(struct context *, char *);
void h_stor(struct context *, char *);
void h_stou(struct context *, char *);
void h_rang(struct context *, char *);
void h_rest(struct context *, char *);
void h_abor(struct context *, char *);
void h_cwd(struct context *, char *);
void h_pwd(struct context *, char *);
void h_syst(struct context *, char *);
void h_stat(struct context *, char *);
void h_help(struct context *, char *);
void h_noop(struct context *, char *);

void h_lprt(struct context *, char *);
void h_lpsv(struct context *, char *);
void h_eprt(struct context *, char *);
void h_epsv(struct context *, char *);

void h_feat(struct context *, char *);
void h_opts(struct context *, char *);
void h_host(struct context *, char *);
void h_mlst(struct context *, char *);
void h_mlsd(struct context *, char *);
void h_lang(struct context *, char *);

void h_esta(struct context *, char *);
void h_estp(struct context *, char *);

#ifdef WITH_SSL
void h_auth(struct context *, char *);
void h_pbsz(struct context *, char *);
void h_prot(struct context *, char *);
void h_ccc(struct context *, char *);
#endif

void h_mff(struct context *, char *);
void h_mfmt(struct context *, char *);

void print_banner(struct context *);

int is_connected(int);
void connect_port(struct context *);
void do_accept_c(struct context *, int);
void accept_data(struct context *, int);
void connect_data(struct context *, int);
void accept_control(struct context *, int);
void buffer2socket(struct context *, int);
void socket2buffer(struct context *, int);
void file2buffer(struct context *, int);
void buffer2file(struct context *, int);
void socket2control(struct context *, int);
void control2socket(struct context *, int);
void do_connect_d(struct context *, int);
void accept_control_raw(int, struct scm_data_accept *);

void ident_connect_out(struct context *, int);
void ident_connected(struct context *, int);
void ident_buffer2socket(struct context *, int);
void ident_socket2buffer(struct context *, int);

void invalid_infn(struct context *, int);
void invalid_outfn(struct context *, int);
int check_gids(struct context *, gid_t);
void cfg_init(void);

char *digest2string(u_char *);

enum list_mode {
    List_nlst, List_list, List_mlsd, List_mlst
};

void list(struct context *, char *, enum list_mode);
void list_stat(struct context *, char *);
void list_mlst(struct context *, char *);

#define CONV_NONE	0
#define CONV_MD5	1
#define CONV_CRC	2
#define CONV_GZ	3

struct visited_dirs;
struct context;

struct context *new_context(struct io_context *);

#define SC (struct context *)

struct list_struct {
    u_int flag;
    char *fact;
};


#ifdef __H_FEAT_C__
#define LIST_ITEM(A,B,C) {A,B,},
#else
#define LIST_ITEM(A,B,C)
#endif

#ifdef __H_FEAT_C__
struct list_struct MLST_fact[] = {
#endif
#define MLST_fact_type	0x0001
    LIST_ITEM(MLST_fact_type, "Type",)
#define MLST_fact_size	0x0002
	LIST_ITEM(MLST_fact_size, "Size",)
#define MLST_fact_modify	0x0004
	LIST_ITEM(MLST_fact_modify, "Modify",)
#define MLST_fact_change	0x0008
	LIST_ITEM(MLST_fact_change, "Change",)
#define MLST_fact_unique	0x0010
	LIST_ITEM(MLST_fact_unique, "Unique",)
#define MLST_fact_perm	0x0020
	LIST_ITEM(MLST_fact_perm, "Perm",)
#define MLST_fact_mediatype	0x0040
	LIST_ITEM(MLST_fact_mediatype, "Media-Type",)
#define MLST_fact_UNIX_mode	0x0080
	LIST_ITEM(MLST_fact_UNIX_mode, "UNIX.mode",)
#define MLST_fact_UNIX_owner	0x0100
	LIST_ITEM(MLST_fact_UNIX_owner, "UNIX.owner",)
#define MLST_fact_UNIX_group	0x0200
	LIST_ITEM(MLST_fact_UNIX_group, "UNIX.group",)
#ifdef __H_FEAT_C__
    { 0, NULL, }
};
#endif

#ifdef __H_FEAT_C__
struct list_struct mode_z_opt[] = {
#endif
#define MODE_Z_ENGINE		0x01
    LIST_ITEM(MODE_Z_ENGINE, "engine",)
#define MODE_Z_METHOD		0x02
	LIST_ITEM(MODE_Z_METHOD, "method",)
#define MODE_Z_LEVEL		0x04
	LIST_ITEM(MODE_Z_LEVEL, "level",)
#define MODE_Z_EXTRA		0x08
	LIST_ITEM(MODE_Z_EXTRA, "extra",)
#define MODE_Z_BLOCKSIZE	0x10
	LIST_ITEM(MODE_Z_BLOCKSIZE, "blocksize",)
#ifdef __H_FEAT_C__
    { 0, NULL, }
};
#endif

typedef long long set64;
#define SET64_ISSET(i,s) (s & (1LL << i))
#define SET64_SET(i,s) (s |= (1LL << i))
#define SET64_CLR(i,s) (s &= ~(1LL << i))
#define SET64_ZERO(s) s = 0LL

struct context {
    struct io_context *io;
    struct buffer *dbuf;	/* buffer for data connection */
    struct buffer *cbufo;	/* outgoing buffer for control connection */
    struct buffer *cbufi;	/* incoming buffer for control connection */
    struct buffer *dbufi;	/* read-only data, ready for processing */
    char *ident_buf;		/* buffer for RFC1413 lookup */
    size_t ident_buflen;	/* internal data for RFC1413 lookup */
    size_t ident_bufoff;	/* internal data for RFC1413 lookup */
    char *user;			/* user name (from USER command) */
    char *email;		/* email address for anonymous ftp */
    char *ident_user;		/* user name (from RFC 1413 lookup) */
#ifdef WITH_DNS
    char *reverse;		/* reverse mapping of client IP */
#endif
    char *vhost;		/* virtual host (HOST vhost/USER user@vhost */
    char root[PATH_MAX + 1];	/* virtual root directory */
    u_int rootlen;		/* length of root */
    dev_t root_dev;		/* device and ... */
    ino_t root_ino;		/* ... inode number of root directory */
    char cwd[PATH_MAX + 1];	/* current working directory */
    char home[PATH_MAX + 1];	/* home directory */
    u_int cwdlen;		/* length of cwd */
    u_int homelen;		/* length of home */
    char filename[PATH_MAX + 1];
    int sctp_fn;		/* sctp socket file number, if any */
    int cfn;			/* control socket file number */
    int dfn;			/* data socket file number */
    int ffn;			/* file file number */
    int dirfn;			/* directory file number */
    int ifn;			/* data socket for RFC 1413 lookups */
    off_t filesize;
    off_t bytecount;
    sockaddr_union sa_c_remote;	/* remote cep of control connection */
    sockaddr_union sa_c_local;	/* local cep of control connection */
    sockaddr_union sa_d_remote;	/* remote cep of data connection */
    sockaddr_union sa_d_estp;	/* remote cep specified by ESTP command */
    struct in6_addr in6_remote;
    struct in6_addr in6_local;
    u_long id;			/* session id */
    int protocol;		/* 0, IPPROTO_TCP, IPPROTO_SCTP */
    time_t transferstart;
    off_t io_offset;
    off_t io_offset_start;
    off_t io_offset_end;
    off_t remaining;		/* number of bytes still to read */
    off_t offset;		/* where to continue reading */
    char *chunk_start;
    size_t chunk_length;
    int authfailures;
    char lastchar;
    char conversion;
    u_int mlst_facts;
#define ST_conn        0
#define ST_user        1
#define ST_pass        2
#define ST_asyncauth   4
    u_int state:3;
    u_int auth_in_progress:1;
    u_int login_logged:1;
    u_int address_mismatch:1;
    u_int accept:1;
    u_int estp:1;
    u_int estp_valid:1;
    u_int passive_transfer:1;
    u_int epsv_all:1;
    u_int transfer_in_progress:1;
    u_int outgoing_data:1;
    u_int use_ascii:1;
    u_int list_to_cc:1;
    u_int is_client:1;
    u_int use_tls_c:1;		/* use ssl on control channel */
    u_int use_tls_d:1;		/* use ssl on data channel */
    u_int last_command_was_rnfr:1;
    u_int buffer_filled:1;	/* actually true for empty buffer, too */
    u_int ascii_in_buffer:1;
    u_int real:1;
    u_int anonymous:1;
    u_int multiline_banners:1;
    u_int umask_set:1;
#ifdef WITH_BZLIB
#endif				/* WITH_BZLIB */
#ifdef WITH_ZLIB
    u_int allow_mode_z:1;
    int deflate_level_min;
    int deflate_level_max;
    int deflate_level_dfl;
#endif				/* WITH_ZLIB */
    u_int md_hash:1;
    struct md_method *md_method_hash;
    struct md_method *md_method_checksum;

    u_int iomode:2;

#define IOMODE_dunno 0
#define IOMODE_sendfile 1
#define IOMODE_mmap 2
#define IOMODE_read 3

    u_int iomode_fixed:1;
    u_int pst_valid:1;

/* START acl dependant configuration variables */
    u_int resolve_ids:1;
    u_int allow_dotfiles:1;
    u_int allow_conv_gzip:1;
    u_int readme_notify:1;
    u_int readme_once:1;
    u_int allow_symlinks:4;
    u_int banner_bye:1;
    u_int welcome_bye:1;
    u_int ident_query:1;

    u_int picky_uidcheck:1;
    u_int picky_gidcheck:1;
    u_int picky_permcheck:1;

    u_int iac_state:2;

    u_int loglevel:8;

    u_int chmod_dirmask:16;
    u_int chmod_filemask:16;

    time_t accept_timeout;
    time_t conn_timeout;
    time_t idle_timeout;
    time_t idle_timeout_dfl;
    time_t idle_timeout_min;
    time_t idle_timeout_max;
    u_long shape_bandwidth;

    int pasv_ports_first;
    int pasv_ports_last;

    int authfailures_max;
    int authfailures_bye;
    u_int umask;

    char *ftpuser;
    char *ftpgroup;
    char *welcome;
    char *readme;
    char *banner;
    char *greeting;
    char *goodbye;
    char *maintainer;
    char *hostname;

    sockaddr_union *passive_addr;
/* END acl dependant configuration variables */

#ifdef WITH_ZLIB
    z_stream *zstream;
    u_int zcrc32;
    int deflate_level;
    u_int deflate_extra:1;
#endif				/* WITH_ZLIB */
    char mode;

    u_int quota_update_on_close:1;
    char *quota_path;
    long long quota_ondisk;
    long long quota_limit;
    long long quota_filesize_before_stor;
    struct visited_dirs *visited_dirs;
    uid_t uid;
    gid_t gid;
    int gids_size;
    gid_t gids[NGROUPS_MAX];
    u_int lang;
    regex_t *incoming;
#ifdef WITH_SSL
    char *certsubj;		/* authenticated certificate subject */
    char *certsubjaltname;	/* authenticated subject alternative name */
    int certdepth;
    SSL *ssl_c;			/* control connection TLS context */
    SSL *ssl_d;			/* data connection TLS context */
#endif				/* WITH_SSL */
    ssize_t ascii_size_limit;
    size_t protected_buffer_size;
    enum list_mode list_mode;
    struct stat pst;
    rb_tree_t *filelist;
    struct timeval tv_shape;
    char *stat_reply;
    union {
	u_int crc32;
	myMD5_CTX md5context;
#ifdef WITH_SSL
	EVP_MD_CTX *mdctx;
#endif
    } checksum;
    set64 requests;
    set64 requests_dunno;
    set64 requests_site;
    set64 requests_site_dunno;
    set64 requests_log;
    set64 requests_site_log;

    long long traffic_files;
    long long traffic_total;
    int count_files;
    int count_total;

    unsigned char iac[3];
};

struct service_req {
    char *cmd;
    void (*handler)(struct context *, char *);
    u_int arg_needed:1;		/* command requires argument */
    u_int changeuid:1;		/* command requires uid change */
    u_int buildpath:1;		/* command argument needs to be checked */
    int help;
    char *acl_default_name;
};

int get_request_index(struct service_req *, char *);

#define ACL_CONNECT	"connect"
#define ACL_SECURE	"secure"
#define ACL_LOGIN	"login"
#define ACL_REAL	"real"
#define ACL_ANON	"anon"

#ifdef __MAIN__
struct service_req requests[] = {
    { "ABOR", h_abor, 0, 0, 0, IDX_ABOR, ACL_LOGIN, },
    { "APPE", h_appe, 1, 1, 1, IDX_APPE, ACL_REAL, },
#ifdef WITH_SSL
    { "AUTH", h_auth, 1, 0, 0, IDX_AUTH, ACL_CONNECT, },
    { "CCC", h_ccc, 0, 0, 0, IDX_CCC, ACL_CONNECT, },
#endif
    { "CDUP", h_cdup, 0, 1, 1, IDX_CDUP, ACL_LOGIN, },
    { "CWD", h_cwd, 1, 1, 1, IDX_CWD, ACL_LOGIN, },
    { "DELE", h_dele, 1, 1, 1, IDX_DELE, ACL_REAL, },
    { "EPRT", h_eprt, 1, 0, 0, IDX_EPRT, ACL_LOGIN, },
    { "EPSV", h_epsv, 0, 0, 0, IDX_EPSV, ACL_LOGIN, },
    { "ESTA", h_esta, 0, 0, 0, IDX_ESTA, ACL_LOGIN, },
    { "ESTP", h_estp, 0, 0, 0, IDX_ESTP, ACL_LOGIN, },
    { "FEAT", h_feat, 0, 0, 0, IDX_FEAT, ACL_CONNECT, },
    { "HASH", h_hash, 0, 0, 0, IDX_HASH, ACL_CONNECT, },
    { "HELP", h_hash, 0, 0, 0, IDX_HASH, ACL_CONNECT, },
    { "HELP", h_help, 0, 0, 0, IDX_HELP, ACL_CONNECT, },
    { "HOST", h_host, 1, 0, 0, IDX_HOST, ACL_CONNECT, },
    { "LANG", h_lang, 0, 0, 0, IDX_LANG, ACL_CONNECT, },
    { "LIST", h_list, 0, 1, 1, IDX_LIST, ACL_LOGIN, },
    { "LPRT", h_lprt, 1, 0, 0, IDX_LPRT, ACL_LOGIN, },
    { "LPSV", h_lpsv, 0, 0, 0, IDX_LPSV, ACL_LOGIN, },
    { "MDTM", h_mdtm, 1, 1, 1, IDX_MDTM, ACL_LOGIN, },
    { "MFF", h_mff, 1, 1, 1, IDX_MFF, ACL_REAL, },
    { "MFMT", h_mfmt, 1, 1, 1, IDX_MFMT, ACL_REAL, },
    { "MKD", h_mkd, 1, 1, 1, IDX_MKD, ACL_LOGIN, },
    { "MLSD", h_mlsd, 0, 1, 1, IDX_MLSD, ACL_LOGIN, },
    { "MLST", h_mlst, 0, 1, 1, IDX_MLST, ACL_LOGIN, },
    { "MODE", h_mode, 1, 0, 0, IDX_MODE, ACL_LOGIN, },
    { "NLST", h_nlst, 0, 1, 1, IDX_NLST, ACL_LOGIN, },
    { "NOOP", h_noop, 0, 0, 0, IDX_NOOP, ACL_LOGIN, },
    { "OPTS", h_opts, 1, 0, 0, IDX_OPTS, ACL_CONNECT, },
    { "PASS", h_pass, 1, 0, 0, IDX_PASS, ACL_CONNECT, },
    { "PASV", h_pasv, 0, 0, 0, IDX_PASV, ACL_LOGIN, },
#ifdef WITH_SSL
    { "PBSZ", h_pbsz, 1, 0, 0, IDX_PBSZ, ACL_CONNECT, },
#endif
    { "PORT", h_port, 1, 0, 0, IDX_PORT, ACL_LOGIN, },
#ifdef WITH_SSL
    { "PROT", h_prot, 1, 0, 0, IDX_PROT, ACL_CONNECT, },
#endif
    { "PWD", h_pwd, 0, 0, 0, IDX_PWD, ACL_LOGIN, },
    { "QUIT", h_quit, 0, 0, 0, IDX_QUIT, ACL_CONNECT, },
    { "RANG", h_rang, 1, 0, 0, IDX_RANG, ACL_LOGIN, },
    { "REIN", h_rein, 0, 0, 0, IDX_REIN, ACL_CONNECT, },
    { "REST", h_rest, 1, 0, 0, IDX_REST, ACL_LOGIN, },
    { "RETR", h_retr, 1, 1, 1, IDX_RETR, ACL_LOGIN, },
    { "RMD", h_rmd, 1, 1, 0, IDX_RMD, ACL_REAL, },
    { "RNFR", h_rnfr, 1, 1, 1, IDX_RNFR, ACL_REAL, },
    { "RNTO", h_rnto, 1, 1, 1, IDX_RNTO, ACL_REAL, },
    { "SITE", h_noop, 1, 0, 0, IDX_SITE, ACL_CONNECT, },
    { "SIZE", h_size, 1, 1, 1, IDX_SIZE, ACL_LOGIN, },
    { "STAT", h_stat, 0, 0, 1, IDX_STAT, ACL_LOGIN, },
    { "STOR", h_stor, 1, 1, 1, IDX_STOR, ACL_LOGIN, },
    { "STOU", h_stou, 0, 1, 1, IDX_STOU, ACL_LOGIN, },
    { "SYST", h_syst, 0, 0, 0, IDX_SYST, ACL_LOGIN, },
    { "TYPE", h_type, 1, 0, 0, IDX_TYPE, ACL_LOGIN, },
    { "USER", h_user, 1, 0, 0, IDX_USER, ACL_CONNECT, },
    { "XCUP", h_cdup, 0, 1, 1, IDX_CDUP, ACL_LOGIN, },
    { "XCWD", h_cwd, 1, 1, 1, IDX_CWD, ACL_LOGIN, },
    { "XMKD", h_mkd, 1, 1, 1, IDX_MKD, ACL_LOGIN, },
    { "XPWD", h_pwd, 0, 0, 0, IDX_PWD, ACL_LOGIN, },
    { "XRMD", h_rmd, 1, 1, 1, IDX_RMD, ACL_REAL, },
    { NULL, NULL, 0, 0, 0, 0, ACL_CONNECT, },
};

struct service_req requests_site[] = {
    { "CHECKMETHOD", h_site_checkmethod, 0, 0, 0, IDX_SITE_CHECKMTH,
     ACL_LOGIN, },
    { "CHECKSUM", h_site_checksum, 0, 1, 1, IDX_SITE_CHECKSUM, ACL_LOGIN, },
    { "CHMOD", h_site_chmod, 1, 1, 1, IDX_SITE_CHMOD, ACL_REAL, },
    { "GROUP", h_site_group, 1, 0, 0, IDX_SITE_GROUP, ACL_REAL, },
    { "GROUPS", h_site_groups, 0, 0, 0, IDX_SITE_GROUPS, ACL_REAL, },
    { "HELP", h_site_help, 0, 0, 0, IDX_SITE_HELP, ACL_CONNECT, },
    { "ID", h_site_id, 0, 0, 0, IDX_SITE_ID, ACL_REAL, },
    { "IDLE", h_site_idle, 0, 0, 0, IDX_SITE_IDLE, ACL_LOGIN, },
    { "UMASK", h_site_umask, 0, 0, 1, IDX_SITE_UMASK, ACL_REAL, },
    { NULL, NULL, 0, 0, 0, 0, ACL_CONNECT, },
};

#else				/* __MAIN__ */
extern struct service_req requests[];
extern struct service_req requests_site[];
#endif				/* __MAIN__ */
#endif				/* __HEADERS_H_ */

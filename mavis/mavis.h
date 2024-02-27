/*
 * mavis.h
 * (C)1998-2023 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * $Id$
 *
 */

#ifndef __MAVIS_H_
#define __MAVIS_H_
#define MAVIS_API_VERSION "5"

#include <sys/types.h>
#include <unistd.h>
#include <sys/time.h>
#ifdef WITH_SYSPOLL
#include <sys/poll.h>
#else
#include <poll.h>
#endif
#include <sys/types.h>
#include <stdarg.h>
#include <setjmp.h>

#include "misc/sysconf.h"

#include "scm.h"
#include "debug.h"
#include "token.h"

#include "misc/io_sched.h"
#include "misc/io_child.h"
#include "misc/pid_write.h"
#include "misc/rb.h"

/* Response codes for MAVIS modules */

/* External + internal interface: */
#define MAVIS_FINAL	0	/* response available */
#define MAVIS_DEFERRED	1	/* response deferred */
#define MAVIS_IGNORE	2	/* ignore response */
#define MAVIS_TIMEOUT	3	/* query timed out */
#define MAVIS_FINAL_DEFERRED	4	/* final response, but don't run scripts twice */

/* Internal interface: */
#define MAVIS_DOWN	16	/* pass request to lower module */

/* Module configuration return codes: */
#define MAVIS_CONF_OK	0	/* configuration succeeded */
#define MAVIS_CONF_ERR	1	/* configuration failed */

/* Initialization return codes: */
#define MAVIS_INIT_OK	0	/* initialization succeeded */
#define MAVIS_INIT_ERR	1	/* initialization failed */

#define BUFSIZE_MAVIS 65000

struct av_char {
	char *name;
	enum token token;
};

#ifdef __MAVIS_MAIN__
struct av_char av_char[] = {
#define AV_CHAR(A,B,C) A,B,C
#else
#define AV_CHAR(A,B,C)
extern struct av_char av_char[];
#endif

#define AV_A_TYPE               0
    AV_CHAR({"TYPE", S_type},)
#define AV_A_MEMBEROF		1
    AV_CHAR({"MEMBEROF", S_memberof},)
#define AV_A_SSHKEYHASH		2
    AV_CHAR({"SSHKEYHASH", S_ssh_key_hash},)
#define AV_A_TIMESTAMP		3
    AV_CHAR({"TIMESTAMP", S_unknown},)
#define AV_A_USER		4
    AV_CHAR({"USER", S_user},)
#define AV_A_DN			5
    AV_CHAR({"DN", S_dn},)
#define AV_A_RESULT             6
    AV_CHAR({"RESULT", S_result},)
#define AV_A_PATH               7
    AV_CHAR({"PATH", S_path},)
#define AV_A_PASSWORD           8
    AV_CHAR({"PASSWORD", S_password},)
#define AV_A_UID                9
    AV_CHAR({"UID", S_uid},)
#define AV_A_GID                10
    AV_CHAR({"GID", S_gid},)
#define AV_A_LIMIT		11
    AV_CHAR({"LIMIT", S_limit},)
#define AV_A_SSHKEY		12
    AV_CHAR({"SSHKEY", S_ssh_key},)
#define AV_A_TRAFFICSHAPING	13
    AV_CHAR({"TRAFFICSHAPING", S_unknown},)
#define AV_A_IPADDR             14
    AV_CHAR({"IPADDR", S_address},)
#define AV_A_QUOTA_LIMIT        15
    AV_CHAR({"QUOTA_LIMIT", S_unknown},)
#define AV_A_QUOTA_PATH         16
    AV_CHAR({"QUOTA_PATH", S_unknown},)
#define AV_A_COMMENT            17
    AV_CHAR({"COMMENT", S_unknown},)
#define AV_A_SSHKEYID		18
    AV_CHAR({"SSHKEYID", S_ssh_key_id},)
#define AV_A_HOME               19
    AV_CHAR({"HOME", S_home},)
#define AV_A_ROOT               20
    AV_CHAR({"ROOT", S_root},)
#define AV_A_SERIAL             21
    AV_CHAR({"SERIAL", S_unknown},)
#define AV_A_FTP_ANONYMOUS	22
    AV_CHAR({"FTP_ANONYMOUS", S_unknown},)
#define AV_A_EMAIL		23
    AV_CHAR({"EMAIL", S_unknown},)
#define AV_A_GIDS		24
    AV_CHAR({"GIDS", S_gids},)
#define AV_A_SERVERIP		25
    AV_CHAR({"SERVERIP", S_server},)
#define AV_A_ARGS		26
    AV_CHAR({"ARGS", S_args},)
#define AV_A_REALM		27
    AV_CHAR({"REALM", S_realm},)
#define AV_A_RARGS		28
    AV_CHAR({"RARGS", S_rargs},)
#define AV_A_ANON_INCOMING	29
    AV_CHAR({"ANON_INCOMING", S_unknown},)
#define AV_A_VHOST		30
    AV_CHAR({"VHOST", S_unknown},)
#define AV_A_UMASK		31
    AV_CHAR({"UMASK", S_umask},)
#define AV_A_USER_RESPONSE	32
    AV_CHAR({"USER_RESPONSE", S_umessage},)
#define AV_A_VERDICT	33
    AV_CHAR({"VERDICT", S_verdict},)
#define AV_A_CLASS		34
    AV_CHAR({"CLASS", S_unknown},)
#define AV_A_PASSWORD_EXPIRY	35
    AV_CHAR({"PASSWORD_EXPIRY", S_unknown},)
#define AV_A_DBPASSWORD		36
    AV_CHAR({"DBPASSWORD", S_unknown},)
#define AV_A_IDENTITY_SOURCE	37
    AV_CHAR({"IDENTITY_SOURCE", S_identity_source},)
#define AV_A_CUSTOM_0		38
    AV_CHAR({"CUSTOM_0", S_custom_0},)
#define AV_A_CUSTOM_1		39
    AV_CHAR({"CUSTOM_1", S_custom_1},)
#define AV_A_CUSTOM_2		40
    AV_CHAR({"CUSTOM_2", S_custom_2},)
#define AV_A_CUSTOM_3		41
    AV_CHAR({"CUSTOM_3", S_custom_3},)
#define AV_A_CALLER_CAP		42
    AV_CHAR({"CALLER_CAP", S_unknown},) // caller capabilitie (":chpw:", possibly others)
#define AV_A_SPARE43			43
    AV_CHAR({"SPARE43", S_unknown},)
#define AV_A_CERTSUBJ			44
    AV_CHAR({"CERTSUBJ", S_unknown},)
#define AV_A_DBCERTSUBJ			45
    AV_CHAR({"DBCERTSUBJ", S_unknown},)
#define AV_A_TACCLIENT			46
    AV_CHAR({"TACCLIENT", S_client},)
#define AV_A_TACMEMBER			47
    AV_CHAR({"TACMEMBER", S_member},)
#define AV_A_TACPROFILE			48
    AV_CHAR({"TACPROFILE", S_unknown},)
#define AV_A_TACTYPE			49
    AV_CHAR({"TACTYPE", S_type},)
#define AV_A_PASSWORD_NEW		50
    AV_CHAR({"PASSWDNEW", S_password_new},)
#define AV_A_CHALLENGE			51
    AV_CHAR({"CHALLENGE", S_unknown},)
#define AV_A_PASSWORD_ONESHOT		52
    AV_CHAR({"PASSWORD_ONESHOT", S_unknown},)
#define AV_A_PASSWORD_MUSTCHANGE	53
    AV_CHAR({"PASSWORD_MUSTCHANGE", S_unknown},)
#define AV_A_SHELL			54
    AV_CHAR({"SHELL", S_shell},)
#define AV_A_CURRENT_MODULE		55
    AV_CHAR({"CURRENT_MODULE", S_unknown},)
#define AV_A_ARRAYSIZE          	56
#ifdef __MAVIS_MAIN__
};
#endif
#define AV_V_TYPE_FTP           	"FTP"
#define AV_V_TYPE_TACPLUS		"TACPLUS"
/* private query types/commands, may not be used in client queries */
#define AV_V_TYPE_PRIVATE_PREFIX	"PRIV_"
#define AV_V_TYPE_PRIVATE_PREFIX_LEN	5
#define AV_V_TYPE_LOGSTATS		"PRIV_LOGSTATS"
#define AV_V_BOOL_TRUE          	"TRUE"
#define AV_V_BOOL_FALSE         	"FALSE"
#define AV_V_RESULT_OK          	"ACK"
#define AV_V_RESULT_FAIL        	"NAK"
#define AV_V_RESULT_ERROR       	"ERR"
#define AV_V_RESULT_NOTFOUND    	"NFD"
#define AV_V_TACTYPE_AUTH		"AUTH"
#define AV_V_TACTYPE_INFO		"INFO"
#define AV_V_TACTYPE_CHPW		"CHPW"
#define AV_V_TACTYPE_CHAL		"CHAL"
typedef struct av_ctx av_ctx;

struct av_ctx {
    char *arr[AV_A_ARRAYSIZE];
    void *app_cb;
    void *app_ctx;
};

typedef struct mavis_ctx mavis_ctx;
struct sym;

struct mavis_action {
    enum token code;
    u_int line;
    union {
	struct mavis_cond *c;	//if (c)
	int a;			// set a = v / unset a
    } a;
    union {
	struct mavis_action *a;	//then a
	char *v;
    } b;
    union {
	struct mavis_action *a;	//else a
    } c;
    struct mavis_action *n;	//a
};

struct mavis_ctx {
    void *handle;
    int (*append)(mavis_ctx *, void *);
    int (*init)(mavis_ctx *);
    int (*parse)(mavis_ctx *, struct sym *, char *);
    int (*send)(mavis_ctx *, av_ctx **);
    int (*recv)(mavis_ctx *, av_ctx **, void *);
    int (*cancel)(mavis_ctx *, void *);
    void *(*drop)(mavis_ctx *);
    mavis_ctx *down;
    mavis_ctx *top;
    int last_result;
    struct mavis_action *script_in;
    struct mavis_action *script_out;
    struct mavis_action *script_interim;
    struct io_context *io;
    char *identity_source_name;
    char *identifier;
    enum token action_error;	// Default: S_reject, optionally S_continue
    enum token action_notfound; // Default: S_continue, optionally: S_reject
#ifdef MAVIS_CTX_PRIVATE
     MAVIS_CTX_PRIVATE
#endif
};

/* Module handling: */
int mavis_method_add(mavis_ctx **, struct io_context *ctx, char *, char *);
int mavis_init(mavis_ctx *, char *);
int mavis_cancel(mavis_ctx *, void *);
int mavis_drop(mavis_ctx *);
int mavis_send(mavis_ctx *, av_ctx **);
int mavis_recv(mavis_ctx *, av_ctx **, void *);
int mavis_parse(mavis_ctx *, struct sym *, char *);

int get_syslog_level(char *);
int get_syslog_facility(char *);

/* Attribute-value handling: */
av_ctx *av_new(void *, void *);
void av_setcb(av_ctx *, void *, void *);
void av_free(av_ctx *);
void av_free_private(av_ctx *);
char *av_get(av_ctx *, int);
void av_set(av_ctx *, int, char *);
void av_setf(av_ctx *, int, char *, ...)
    __attribute__((format(printf, 3, 4)));
#define av_unset(A,B) av_set(A,B, NULL)
void av_clear(av_ctx *);
void av_dump(av_ctx *);
void av_move(av_ctx *, av_ctx *);
void av_merge(av_ctx *, av_ctx *);
void av_copy(av_ctx *, av_ctx *);
size_t av_array_to_char_len(av_ctx *);
int av_array_to_char(av_ctx *, char *, size_t, fd_set *);
int av_char_to_array(av_ctx *, char *, fd_set *);
int av_attribute_to_i(char *);
int av_attr_token_to_i(struct sym *);

char *av_addserial(av_ctx *);

#define MAX_INPUT_LINE_LEN 4096

struct token_chain;

struct sym {
    char *filename;
    char buf[MAX_INPUT_LINE_LEN];	/* parse buffer */
    char *start;
    char *raw;
    int pos;			/* current place in buf */
    u_int line:29;		/* current line number for parsing */
    u_int flag_parse_pcre:1;
    u_int flag_prohibit_include:1;
    u_int quoted:1;
    char ch[4];			/* current parse character */
    char chlen;			/* current parse character length */
    enum token code;		/* parser output */
    char *in;			/* input buffer start */
    int len;			/* input buffer length */
    char *tin;			/* pointer to remaining input buffer */
    int tlen;			/* length of remaining input buffer */
    jmp_buf env;		/* saved stack context for parse errors */
    int env_valid;
    struct token_chain *token_chain;
    struct sym *next;
};

void parse_error(struct sym *, char *, ...);
void parse_error_expect(struct sym *, ...);
enum token parse_permission(struct sym *);
u_int parse_bool(struct sym *);
void parse(struct sym *, enum token);
void getsym(struct sym *);
void buf_add(struct sym *, char);
void sym_get(struct sym *);
enum token sym_peek(struct sym *);
void cfg_read_config(char *, void (*)(struct sym *), char *);
enum token keycode(char *);
int parse_int(struct sym *);
u_int parse_uint(struct sym *);
int parse_seconds(struct sym *);
void sym_init(struct sym *);
void report_cfg_error(int, int, char *, ...)
    __attribute__((format(printf, 3, 4)));
void parse_debug(struct sym *, u_int *);
int parse_comma(struct sym *);

void parse_userid(struct sym *, uid_t *, gid_t *);
void parse_groupid(struct sym *, gid_t *);
void parse_umask(struct sym *, mode_t *);

void parse_mavispath(struct sym *);
int parse_mavismodule(mavis_ctx **, struct io_context *, struct sym *);

struct common_data {
    struct io_context *io;
    char *progname;
    char *progpath;
    char *version;
    u_int version_only;
    u_int parse_only;
    u_int debug;
    u_int debug_redirected;
    int syslog_level;
    int syslog_facility;
    u_int syslog_dflt:1;
    unsigned long long regex_match_case;
#if defined(WITH_PCRE) || defined(WITH_PCRE2)
    int regex_pcre_flags;
#endif
    int regex_posix_flags;
    char *syslog_ident;
    char *proctitle;
    char *coredumpdir;
    char *gcorepath;
    char *debug_cmd;
    int debugtty;
    pid_t pid;
    int users_min;
    int users_max;
    int users_cur;
    int users_max_total;
    int servers_min;
    int servers_max;
    int servers_cur;
    char *font_black;
    char *font_red;
    char *font_green;
    char *font_yellow;
    char *font_blue;
    char *font_magenta;
    char *font_cyan;
    char *font_white;
    char *font_plain;
    char *font_bold;
    u_long ipc_key;
    char *ipc_url;
    char **argv;
    char **envp;
    struct pidfile *pidfile;
    int singleprocess;
    char *conffile;
    char *id;
    time_t cleanup_interval;
    int (*scm_send_msg)(int, struct scm_data *, int);
    int (*scm_recv_msg)(int, struct scm_data_accept *, size_t, int *);
    void (*scm_accept)(int, struct scm_data_accept *);
};

extern struct common_data common_data;

#define case_CC_Tokens \
        case S_trace:\
        case S_debug:\
        case S_syslog:\
        case S_proctitle:\
        case S_coredump: parse_common(sym); continue

void init_common_data(void);
void parse_common(struct sym *);
void common_usage(void);

void mavis_script_parse(mavis_ctx *, struct sym *);
enum token mavis_script_eval(mavis_ctx *, av_ctx *, struct mavis_action *);
void mavis_script_drop(struct mavis_action **);

struct mavis_tm {
    struct mavis_tm *next;
    char *string;
    unsigned long long min;	/* minute, 0-59 */
    unsigned long hour;		/* hour, 0-23 */
    unsigned long mday;		/* day of month, 1-31 */
    unsigned long mon;		/* month, 1-12 */
    unsigned long wday;		/* day of week, 1-7 */
};

struct mavis_timespec {
    struct mavis_tm *tm;
    char *string;
    int matched;		/* 0 == no match */
    time_t valid_until;
    char name[1];
};

int eval_timespec(struct mavis_timespec *, char **);

int parse_cron(struct mavis_tm *, char *);
void parse_timespec(rb_tree_t *, struct sym *);
struct mavis_timespec *find_timespec(rb_tree_t *, char *);
rb_tree_t *init_timespec(void);

char *escape_string(char *, size_t, char *, size_t *);

int sym_normalize_cond_start(struct sym *, struct sym **);
void sym_normalize_cond_end(struct sym **);

struct mavis_cond_multi {
    int n;
    struct mavis_cond *e[8];
};

struct mavis_cond_single {
    enum token token;
    void *lhs;
    char *lhs_txt;
    void *rhs;
    char *rhs_txt;
};

struct mavis_cond {
    enum token type;
    u_int line;
    union {
	struct mavis_cond_single s;
	struct mavis_cond_multi m;
    } u;
};

struct mavis_cond *mavis_cond_new(struct sym *, enum token);
struct mavis_cond *mavis_cond_add(struct mavis_cond *a, struct mavis_cond *);
struct mavis_action *mavis_action_new(struct sym *sym);

void mavis_cond_optimize(struct mavis_cond **);

int cfg_open_and_read(char *, char **, int *);
int cfg_close(char *, char *, int);
int ipc_create(char *, int);
void ipc_delete(void);

int mavis_check_version(char *);

void mavis_detach(void);

void mavis_module_parse_action(mavis_ctx *, struct sym *);

#define MAVIS_EXT_MAGIC_V1 0x4d610001
struct mavis_ext_hdr_v1 {
    uint32_t magic;
    uint32_t body_len;
    uint32_t result;
} __attribute__((__packed__));

#if defined(MAVIS_name) && defined(DEBUG)
#undef DebugIn
#undef DebugOut
#define DebugIn(A) Debug  ((A, "+ "MAVIS_name":%s\n", __func__))
#define DebugOut(A) Debug ((A, "- "MAVIS_name":%s\n", __func__))
#endif

#define CHAREOF (char)EOF

#endif				/* __MAVIS_H_ */

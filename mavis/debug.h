/* debug.h (C)1998-2011 by Marc Huber <Marc.Huber@web.de>
 *
 * $Id: debug.h,v 1.13 2020/12/05 14:24:01 marc Exp marc $
 *
 */

#ifndef __DEBUG_H_
#define __DEBUG_H_

#include "misc/sysconf.h"

#define DebugIn(A) Debug ((A, "+ %s\n", __func__))
#define DebugOut(A) Debug ((A, "- %s\n", __func__))

#ifdef DEBUG
#define Debug(A) debug A
#else
#define Debug(A)
#endif

void debug(u_long, char *, ...) __attribute__((format(printf, 2, 3)));
int debug_conf(int, char **);
void debug_setpid(void);

/* Debugging flags */
#define DEBUG_PARSE_FLAG    (1<<0)	/* 1 */
#define DEBUG_AUTHOR_FLAG   (1<<1)	/* 2 */
#define DEBUG_AUTHOR DEBUG_AUTHOR_FLAG
#define DEBUG_AUTHEN_FLAG   (1<<2)	/* 4 */
#define DEBUG_AUTH DEBUG_AUTHEN_FLAG
#define DEBUG_ACCT_FLAG     (1<<3)	/* 8 */
#define DEBUG_ACCT DEBUG_ACCT_FLAG
#define DEBUG_CONFIG_FLAG   (1<<4)	/* 16 */
#define DEBUG_PACKET_FLAG   (1<<5)	/* 32 */
#define DEBUG_PACKET DEBUG_PACKET_FLAG
#define DEBUG_HEX_FLAG      (1<<6)	/* 64 */
#define DEBUG_LOCK_FLAG     (1<<7)	/* 128 */
#define DEBUG_LOCK DEBUG_LOCK_FLAG
#define DEBUG_REGEX_FLAG    (1<<8)	/* 256 */
#define DEBUG_ACL_FLAG      (1<<9)	/* 512 */
#define DEBUG_ACL DEBUG_ACL_FLAG
#define DEBUG_RADIUS_FLAG   (1<<10)	/* 1024 */
#define DEBUG_CMD_FLAG      (1<<11)	/* 2048 */
#define DEBUG_COMMAND DEBUG_CMD_FLAG
#define DEBUG_BUFFER_FLAG   (1<<12)	/* 4096 */
#define DEBUG_BUFFER DEBUG_BUFFER_FLAG
#define DEBUG_PROC_FLAG     (1<<13)	/* 8192 */
#define DEBUG_PROC DEBUG_PROC_FLAG
#define DEBUG_NET_FLAG      (1<<14)	/* 16k */
#define DEBUG_NET	DEBUG_NET_FLAG
#define DEBUG_PATH_FLAG      (1<<15)	/* 32k */
#define DEBUG_PATH DEBUG_PATH_FLAG
#define DEBUG_CONTROL_FLAG      (1<<16)	/* 64k */
#define DEBUG_CONTROL DEBUG_CONTROL_FLAG
#define DEBUG_INDEX_FLAG      (1<<17)	/* 128k */
#define DEBUG_INDEX DEBUG_INDEX_FLAG
#define DEBUG_AV_FLAG      (1<<18)	/* 256k */
#define DEBUG_AV DEBUG_AV_FLAG
#define DEBUG_MAVIS_FLAG      (1<<19)	/* 512k */
#define DEBUG_MAVIS DEBUG_MAVIS_FLAG
#define DEBUG_LWRES_FLAG      (1<<20)	/* 1024k */
#define DEBUG_LWRES DEBUG_LWRES_FLAG
#define DEBUG_USERINPUT_FLAG      (1<<21)	/* 2048k */
#define DEBUG_USERINPUT DEBUG_USERINPUT_FLAG

#define DEBUG_NONE_FLAG     ((u_int)1<<31)	/* 2147483648 */

#define DEBUG_ALL_FLAG	(~DEBUG_NONE_FLAG & ~DEBUG_USERINPUT_FLAG)
#define DEBUG_ALL DEBUG_ALL_FLAG
#endif

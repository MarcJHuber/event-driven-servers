/*
 * log.h
 * (C)1998-2011 by Marc Huber <Marc.Huber@web.de>
 *
 * $Id: log.h,v 1.8 2011/02/27 12:22:16 marc Exp $
 *
 */

#ifndef __LOG_H__
#define __LOG_H__

#ifndef __GNUC__
#define __attribute__(A)
#endif				/* __GNUC__ */

void logopen(void);
void logmsg(char *, ...) __attribute__((format(printf, 1, 2)));
void logerr(char *, ...) __attribute__((format(printf, 1, 2)));
#endif				/* __LOG_H__ */

/*
 * mysendfile.h
 * 
 * (C)2001-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 * 
 * $Id: mysendfile.h,v 1.7 2011/02/27 12:22:16 marc Exp $
 */

#if defined(WITH_SENDFILE) && !defined(__MY_SENDFILE_H__)
#define __MY_SENDFILE_H__
#include <sys/types.h>
ssize_t mysendfile(int, int, off_t *, size_t);
#endif

/* crc32.h (C)2000 Marc Huber <Marc.Huber@web.de>
 *
 * $Id: crc32.h,v 1.4 2008/05/19 18:46:15 marc Exp $
 *
 */

#ifndef __CRC32_H_
#define __CRC32_H_
#include <stdint.h>
#include <sys/types.h>

#define INITCRC32  0		/* Initial CRC value */

u_int crc32_update(uint32_t, u_char *, off_t);
u_int crc32_final(uint32_t, off_t);
#endif				/* __CRC32_H_ */

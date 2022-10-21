/*******************************************************************************
 * $Id: sysconf.h,v 1.72 2011/09/14 13:06:46 marc Exp marc $
 *
 * sysconf.h
 * (C) 2000-2011 by Marc Huber <Marc.Huber@web.de>
 * All rights reserved.
 *
 * OS specific definitions.
 *
 * Most of the software you'll find in the package should compile fine for
 * most real operating systems (MacOS/Darwin, Sun Solaris, FreeBSD, OpenBSD,
 * NetBSD, DragonFly BSD, Linux), both in 32 and 64bit variants. Cygwin is
 * semi-supported (in a degarded mode, due to lack of file descriptor
 * passing).
 *
 * The version number checking below is partially based on more or less
 * educated guessing.
 *
 ******************************************************************************/
#if !defined(__SYSCONF_H__)
#define __SYSCONF_H__
/*******************************************************************************
 * BSD summary define
 */
#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) || defined(__APPLE__) || defined(__DragonFly__)
#define __ANY_BSD__
#endif
/*******************************************************************************
 * Sun Forte 6 C defines __sun, but we prefer __sun__ for GCC compatibility.
 * Plus, the compiler doesn't understand "__inline__", but accepts "inline".
 */
#if defined(__SUNPRO_C)
#if !defined(__sun__) && defined(__sun)
#define __sun__
#endif
#define __inline__ inline
#endif
/*******************************************************************************
 * Intel(R) C++ Compiler for 32-bit applications
 *
 * Version 6.0 and higher:
 * The evaluation and non-commercial copies are free and seem to work fine. You
 * may need to set LD_LIBRARY_PATH to wherever your Intel shared libraries are.
 *
 * Older versions of icc don't support ISO standard C99:
 */
#if defined(__INTEL_COMPILER) && __INTEL_COMPILER < 800
#define __func__ __FUNCTION__
#endif
/*******************************************************************************
 * Non-C99 compliant gcc versions. Guessing about the minor version number.
 */
#if defined(__GNUC__) && __GNUC__ < 3 && __GNUC_MINOR__ < 95
#define __func__ __FUNCTION__
#endif
/*******************************************************************************
 * Don't attempt to use GNU-C extensions if we're not using GCC ...
 */
#if !defined(__GNUC__)
#define __attribute__(A)
#endif
/* ... or compatible. */
#if defined(__INTEL_COMPILER) && __INTEL_COMPILER > 1000
#undef __attribute__
#endif
/*******************************************************************************
 * For SUN Solaris, XPG-4.2 (aka. UNIX-95) extensions need to be enabled
 * for ancillary messages. We only want XPG-4.2 to be defined for one
 * particular file, and there shouldn't be any need to link the xpg library,
 * as the required functionality is in fact part of the kernel.
 */
#if defined(__sun__) && defined(__SCM_C__)
#include <sys/types.h>
#define _XOPEN_SOURCE
#define _XOPEN_SOURCE_EXTENDED 1
#define _XPG4_2
/*
 * Had to define _XPG6 for Solaris-10 ... seems to break SXDE, however.
 * #  define _XPG6
 */
/*
 * For Solaris 2.6, <sys/socket.h> features some more weirdness ...
 */
#if OSLEVEL < 0x05070000
#define recvmsg __xnet_recvmsg
#define sendmsg __xnet_sendmsg
#endif
#endif
/******************************************************************************/
#include <dlfcn.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <fcntl.h>
#if defined(__linux__)
/* need to #include this before the openssl stuff ... */
#define __USE_XOPEN
#include <unistd.h>
#undef __USE_XOPEN
#endif
#if defined(WITH_SSL)
#include <openssl/ssl.h>
#endif
/*******************************************************************************
 * Endianess:
 */
#if defined(__sun__)
#include <sys/isa_defs.h>
#ifndef __LITTLE_ENDIAN
#define __LITTLE_ENDIAN 1234
#endif
#ifndef __BIG_ENDIAN
#define __BIG_ENDIAN    4321
#endif
#if defined(_BIG_ENDIAN)
#define __BYTE_ORDER __BIG_ENDIAN
#else
#define __BYTE_ORDER __LITTLE_ENDIAN
#endif
#endif
#if defined(__linux__)
#include <endian.h>
#endif
#if defined(__ANY_BSD__)
#include <machine/endian.h>
#ifndef __LITTLE_ENDIAN
#define __LITTLE_ENDIAN 1234
#endif
#ifndef __BIG_ENDIAN
#define __BIG_ENDIAN    4321
#endif
#if BYTE_ORDER == LITTLE_ENDIAN
#define __BYTE_ORDER __LITTLE_ENDIAN
#else
#define __BYTE_ORDER __BIG_ENDIAN
#endif
#endif
/*******************************************************************************
 * Prototype for crypt(3)
 */
#if (!defined(WITH_SSL) || OPENSSL_VERSION_NUMBER >= 0x00907000L)
#if defined(__sun__)
#undef des_crypt
#include <crypt.h>
#endif
#if defined(__ANY_BSD__)
#include <unistd.h>
#endif
#if defined(__CYGWIN__)
#include <crypt.h>
#endif
#else
/* Use crypt(3) from libcrypto */
#ifdef WITH_LIBCRYPT
#undef WITH_LIBCRYPT
#endif
#endif
/*******************************************************************************
 * Has struct flock a l_sysid member? I guess that's specific to Solaris.
 */
#if defined(__sun__)
#define WITH_FLOCK_L_SYSID
#endif
/*******************************************************************************
 * Is dirfd() available?
 */
#if defined(__linux__)
#define WITH_DIRFD
#endif
#if defined(__sun__)
#define WITH_DIRFD
#if OSLEVEL < 0x050b0000	/* guessing, again */
#if !defined(_POSIX_C_SOURCE) && !defined(_XOPEN_SOURCE)
#define dirfd(A) A->dd_fd
#else
#define dirfd(A) A->d_fd
#endif
#endif
#endif
#if defined(__ANY_BSD__)
#define WITH_DIRFD
#endif
/*******************************************************************************
 * IPv6 stuff
 */
#if !defined(s6_addr32)
/*
 * Solaris 8 protects s6_addr32 with _KERNEL:
 */
#if defined(__sun__)
#define s6_addr32	_S6_un._S6_u32
#endif
/*
 * The BSDs have different naming conventions:
 */
#if defined(__ANY_BSD__)
#define s6_addr32	__u6_addr.__u6_addr32
#endif
#if defined(__DragonFly__)
#undef s6_addr32
#define s6_addr32	_s6_addr32
#endif
#endif
/*******************************************************************************
 * Suns prototype for the PAM conversion function differs from Linux PAM
 * and OpenPAM:
 */
#if defined(__sun__)
#define PAM_CONV_ARG2_TYPE struct pam_message
#else
#define PAM_CONV_ARG2_TYPE const struct pam_message
#endif
/*******************************************************************************
 * getgrouplist(3) isn't standard, but available on some systems.
 *
 * While my custom routines work equally well, getgrouplist(3) would add the
 * automatically generated groups on MacOS. These don't seem to be present
 * otherwise.
 *
 * Alas, there are at least two prototypes in the wild, and Solaris doesn't
 * support getgrouplist(3) at all, so it's currently safer to fall back to
 * my custom implementation. Performance-wise, this doesn't matter.
 */
#if 0
#if defined(__linux__)
#define HAVE_GETGROUPLIST
#define GETGROUPLIST_ARG2_TYPE gid_t
#endif
#if defined(__ANY_BSD__)
#define HAVE_GETGROUPLIST
#define GETGROUPLIST_ARG2_TYPE int
#endif
#endif
/*******************************************************************************
 * The BSDs don't need to define O_LARGEFILE. Set it to 0 if undefined.
 */
#if !defined(O_LARGEFILE)
#define O_LARGEFILE 0
#endif
/*******************************************************************************
 * O_NOFOLLOW is defined on FreeBSD and Linux. Set to 0 if not defined.
 */
#if !defined(O_NOFOLLOW)
#define O_NOFOLLOW 0
#endif
/*******************************************************************************
 * If and where to find basename(3):
 */
#if defined(__linux__)
#define WITH_BASENAME
#define WITH_BASENAME_LIBGEN
#endif
#if defined(__sun__)
#define WITH_BASENAME
#define WITH_BASENAME_LIBGEN
#endif
#if defined(__ANY_BSD__)
#define WITH_BASENAME
#define WITH_BASENAME_LIBGEN
#endif
/*******************************************************************************
 * UNIX_PATH_MAX
 */
#if !defined(UNIX_PATH_MAX)
#define UNIX_PATH_MAX 108
#endif
/*******************************************************************************
 * INET6_ADDRSTRLEN
 */
#if !defined(INET6_ADDRSTRLEN)
#define INET6_ADDRSTRLEN 46
#endif
/*******************************************************************************
 * INADDR_NONE
 */
#if !defined(INADDR_NONE)
#define INADDR_NONE ((unsigned int) -1)
#endif
/*******************************************************************************
 * mmap(2)
 */
#if !defined(WITH_MMAP)
#if defined(__sun__)
#define WITH_MMAP
#endif
#if defined(__linux__)
#define WITH_MMAP
#endif
#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__APPLE__) || defined(__DragonFly__)
#define WITH_MMAP
#endif
#if defined(__NetBSD__) && OSLEVEL >= 0x01040000
#define WITH_MMAP
#endif
#endif
#if defined(WITH_MMAP)
#include <sys/mman.h>
#if !defined(MADV_NORMAL) && defined(POSIX_MADV_NORMAL)
#define madvise posix_madvise
#define MADV_NORMAL		POSIX_MADV_NORMAL
#define MADV_RANDOM		POSIX_MADV_RANDOM
#define MADV_WILLNEED	POSIX_MADV_WILLNEED
#define MADV_DONTNEED	POSIX_MADV_DONTNEED
#define MADV_SEQUENTIAL	POSIX_MADV_SEQUENTIAL
#endif
#if !defined(MADV_NORMAL)
#define madvise(A,B,C)	{}
#define MADV_NORMAL		0
#define MADV_RANDOM		0
#define MADV_WILLNEED	0
#define MADV_DONTNEED	0
#define MADV_SEQUENTIAL	0
#endif
#endif
/*******************************************************************************
 * 64bit architecture? Solaris defines _LP64, Linux __WORDSIZE, FreeBSD
 * ELF_WORD_SIZE, apparently. Don't know about the others ... could probably
 * check for machine architecture.
 */
#if defined(__linux__) && defined(__WORDSIZE) && __WORDSIZE == 64
#ifndef _LP64
#define _LP64
#endif
#endif
#if defined(__FreeBSD__)
#include <machine/elf.h>
#if defined(__ELF_WORD_SIZE) && ELF_WORD_SIZE == 64
#ifndef _LP64
#define _LP64
#endif
#endif
#endif
/*******************************************************************************
 * Size of off_t:
 *
 * Actually, the GNU C library defines __USE_FILE_OFFSET64 in <features.h>.
 */
#if !defined(__USE_FILE_OFFSET64)
#if defined(_FILE_OFFSET_BITS) && _FILE_OFFSET_BITS == 64
/* Compiled with -D_FILE_OFFSET_BITS=64 */
#define __USE_FILE_OFFSET64
#endif
#endif
#if !defined(__USE_FILE_OFFSET64)
#if defined(_LP64)
/* 64bit machines, e.g. Sun Sparc with 64bit compiler */
#define __USE_FILE_OFFSET64
#endif
#endif
#if !defined(__USE_FILE_OFFSET64)
#if defined(__ANY_BSD__)
/* The BSDs have a 64bit off_t by default */
#define __USE_FILE_OFFSET64
#endif
#endif
/*******************************************************************************
 * sendfile(2)
 */
#if defined(__linux__) && OSLEVEL >= 0x02020000
#define WITH_SENDFILE
#endif
#if defined(__linux__) && OSLEVEL >= 0x02050006
#define WITH_SENDFILE64
#endif
#if defined(__FreeBSD__) && OSLEVEL >= 0x03000000
#define WITH_SENDFILE
#endif
#if defined(__APPLE__)
#define WITH_SENDFILE
#endif
#if defined(__DragonFly__)
#define WITH_SENDFILE
#endif
/*******************************************************************************
 * alloca(3) prototype:
 */
#if defined(__sun__) || defined(__linux__)
#include <alloca.h>
#endif
#if defined(__ANY_BSD__)
#include <stdlib.h>
#endif
/*******************************************************************************
 * Shadow passwords, password handling routines:
 */
#if defined(__sun__) || defined(__linux__)
#define WITH_SHADOWPWD
#endif
/*******************************************************************************
 * BSDs have a sun_len field in struct sockaddr_un:
 */
#if defined(__ANY_BSD__)
#define HAS_SUN_LEN
#endif
/*******************************************************************************
 * Some systems actually come with a working setproctitle implementation:
 */
#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) || defined(__DragonFly__)
#define HAVE_SETPROCTITLE
#endif
#if defined(__FreeBSD__) && OSLEVEL < 0x04000000
#include <libutil.h>
#endif
/* Others need to use our custom implementation: */
#if defined(__linux__) || defined(__APPLE__)
#define WANT_SETPROCTITLE
#endif
/*******************************************************************************
 * On non-ELF systems, an underscore needs to be prepended to dynamic library
 * symbol names. We're going to need that for dlsym().
 */
#if !defined(__ELF__)
#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) || defined(__DragonFly__)
#define DLSYM_PREFIX "_"
#endif
#endif
#if !defined(DLSYM_PREFIX)
#define DLSYM_PREFIX ""
#endif
/*******************************************************************************
 * socklen_t is unavailable on older systems:
 */
#if defined(__sun__) && OSLEVEL < 0x05070000
#define socklen_t size_t
#endif
#if defined(__NetBSD__) && OSLEVEL < 0x01040000
#define socklen_t size_t
#endif
/*******************************************************************************
 * Some systems have AF_INET6 defined, but in fact don't support IPv6:
 */
#if defined(__FreeBSD__) && OSLEVEL < 0x04000000
#undef AF_INET6
#endif
#if defined(__NetBSD__) && OSLEVEL < 0x01050000
#undef AF_INET6
#endif
/*******************************************************************************
 * Double-check for SCTP
 */
#ifndef AF_SCTP
#undef WITH_SCTP
#endif
/*******************************************************************************
 * OpenBSD doesn't define RTLD_GLOBAL
 */
#if !defined(RTLD_GLOBAL)
#define RTLD_GLOBAL 0
#endif
/*******************************************************************************
 * Cygwin still lacks file descriptor passing.
 * FIXME. This is from at least a decade ago. Verify.
 * OTOH, the software runs just fine on the Linux Subsystem for Windows, so
 * bothering about this is likely not worth it ...
 */
#if defined(__CYGWIN__)
#define BROKEN_FD_PASSING
#endif
/*******************************************************************************
 * time_t on OpenBSD is 64 bit since 5.5
 */
#if defined(__OpenBSD__) && OSLEVEL >= 0x5050000
#define TIME_T_PRINTF "%lld"
#else
#define TIME_T_PRINTF "%ld"
#endif
/*******************************************************************************
 * VRF handling
 */
#if defined(__linux__) && defined(SO_BINDTODEVICE)
#define VRF_BINDTODEVICE
#endif
#if defined(__OpenBSD__) && defined(SO_RTABLE)
#define VRF_RTABLE
#endif
#if defined(__FreeBSD__) && defined(SO_SETFIB)
#define VRF_SETFIB
#endif
/*******************************************************************************
 * misc
 */
#ifndef LOG_PRIMASK
#define LOG_PRIMASK 0x07
#endif
/******************************************************************************/
#endif				/* __SYSCONF_H__ */

############################################################## vim: ft=make ts=4
# Makefile.inc
# (C) 1997-2009 Marc Huber <Marc.Huber@web.de>
################################################################################

ifeq ($(MAKEFILE_INC_INCLUDED),)
MAKEFILE_INC_INCLUDED=1

TR	= /usr/bin/tr

ifneq ($(wildcard /usr/xpg4/bin/tr),)
	TR	= /usr/xpg4/bin/tr
endif

OSs	:= $(shell uname -s | env -i $(TR) "[:upper:]/ " "[:lower:]--")
OSr	:= $(shell uname -r | sed "s/(.*)//" | env -i $(TR) "[:upper:]/ " "[:lower:]--")
OSm	:= $(shell uname -m | env -i $(TR) "[:upper:]/ " "[:lower:]--")
OS	:= $(OSs)-$(OSr)-$(OSm)
OSTYPE	:= $(shell echo $(OSs) | sed "s/-.*//")
OSLEVEL	:= $(shell printf "0x%.2x%.2x%.4x" `echo $(OSr) | env -i $(TR) -c "[:digit:]" "[ *]"` 0 0 0 | cut -c-10)

MF_OBJ=build/Makefile.inc.$(OS)
ifeq ($(wildcard $(MF_OBJ)),)
	MF_OBJ=../build/Makefile.inc.$(OS)
	ifeq ($(wildcard $(MF_OBJ)),)
		MF_OBJ=../../build/Makefile.inc.$(OS)
		ifeq ($(wildcard $(MF_OBJ)),)
			MF_OBJ=../../../build/Makefile.inc.$(OS)
			ifeq ($(wildcard $(MF_OBJ)),)
$(error Please run the configure script to create Makefile.inc.$(OS))
			endif
		endif
	endif
endif

include $(MF_OBJ)

ifeq ($(origin CC),default)
	ifneq ($(shell clang $$1 -v 2>&1),)
		CC = clang
		CC_GCC		= 1
		CC_CLANG	= 1
	endif
endif

ifeq ($(origin CC),default)
	ifneq ($(shell gcc $$1 -v 2>&1),)
		CC = gcc
		CC_GCC		= 1
	endif
endif

CCV = $(shell set $(CC); $$1 -v 2>&1)

ifneq ($(findstring "Sun C",$(CCV)),)
	CC_SUN		= 1
endif

ifneq ($(findstring "clang",$(CCV)),)
	CC_CLANG		= 1
	CC_GCC		= 1
endif

ifneq ($(findstring "gcc",$(CCV)),)
	CC_GCC		= 1
endif

LD	?= ld

LDV = $(shell set $(LD); $$1 -v 2>&1)

ifeq ($(findstring GNU,$(LDV)),)
	LD_GNU	= 0
else
	LD_GNU	= 1
endif

ifeq ($(CC_GCC),1)
	CFLAGS		?= -Wall -W -Wno-strict-prototypes -Wno-implicit-fallthrough
	ifeq ($(CC_CLANG),1)
		CFLAGS		+= -O2 # CLANG outputs correct code, GGC doesn't.
	else
$(warning It lookt like your're using GCC. Code optimizations via -O are turned off for now.)
	endif
	CFLAGS_PIC	?= -fPIC

	LDOPT_R		?= -Wl,-rpath,
	LD_SHARED	= $(CC) -shared
	ifeq ($(DEBUG),1)
		CFLAGS	+= -Werror
		CFLAGS	+= -Wno-deprecated-declarations
		CFLAGS	+= -Wno-unused-result
	endif
endif

ifeq ($(CC_SUN),1)
	#CFLAGS		?= -O -errwarn
	CFLAGS		?= -O
	CFLAGS_PIC	?= -G
	LDOPT_R		?= -Wl,-rpath,
	LD_SHARED	= $(CC) $(CFLAGS_PIC)
endif

SHLIB_PRE	= lib
SHLIB_EXT	= .so

ifeq ($(OSTYPE), darwin)
	LD_SHARED	= $(CC) -dynamiclib 
	ifeq ($(CC_GCC), 1)
	# CFLAGS		+= -Wno-shorten-64-to-32
	# CFLAGS		+= -arch i386 -arch x86_64 -arch ppc -arch ppc64
		ifeq ($(shell expr 11 - `uname -r | cut -c-2` \<= 0), 1)
			# MacOS 10.7 deprecates a couple of SSL functions. Disable compiler warnings.
			CFLAGS	+= -Wno-deprecated-declarations
		endif
	endif
	SHLIB_EXT	= .dylib
	LIB_MAVIS	= '$(LDOPT_R)@loader_path/../lib'
endif

ifeq ($(OSTYPE), cygwin_nt)
	CFLAGS_PIC	=
	SHLIB_PRE	= cyg
	SHLIB_EXT	= .dll
	EXEC_EXT	= .exe
endif

CFLAGS += $(AUX_CFLAGS)

INSTALL	?= install -c

ifeq ($(OSTYPE), sunos)
	ifdef LD_LIBRARY_PATH
$(error LD_LIBRARY_PATH may not be set for Solaris)
	endif
	LIB_NET	= -lnsl -lsocket
	ifeq ($(LD_GNU), 0)
		LDOPT_R	= -R
		LD_SHARED = $(LD) -G -z textwarn
	endif
	ifneq ($(CC_GCC), 1)
		CFLAGS	?= -xO3 -xstrconst -xdepend -Xa -errwarn=%all
		CFLAGS_PIC = -KPIC
	endif
	DEF	+= -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64
	INSTALL = /usr/bin/ginstall
	ifeq ($(wildcard $(INSTALL)),)
		INSTALL = /usr/ucb/install
	endif
	ifeq ($(wildcard $(INSTALL)),)
		INSTALL = /usr/bin/install
	endif
	LIB_MAVIS	= '$(LDOPT_R)$$ORIGIN/../lib'
endif

ifeq ($(OSTYPE), linux)
	DEF	+= -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64
	LIB_MAVIS	= '$(LDOPT_R)$$ORIGIN/../lib$(LIBARCH)'
endif

DEF	+= -DOSTYPE=$(OSTYPE) -DOSLEVEL=$(OSLEVEL) -DOS="\"$(OS)\""

ifeq ($(DEBUG),1)
	DEF	+= -DDEBUG
	CFLAGS	+= -g -Og
	ifeq ($(CC_GCC), 1)
		CFLAGS	+= -ggdb
	endif
	CC_GCC	= 1
endif

DIR_MAVIS	= $(BASE)/mavis
LIB_MAVIS	+= "-L$(BASE)/build/$(OS)/mavis" "$(LDOPT_R)$(LIBARCHDIR_DEST)" -lmavis
DIR_MISC	= $(BASE)/misc
INC			+= -I$(BASE)

# Check for c-ares library:

# Try pkg-config first:
ifeq ($(WITH_ARES),)
	ifeq ($(shell pkg-config --exists libcares 2>/dev/null ; echo $$?),0)
		WITH_ARES=1
		LIBDIR_ARES=$(shell pkg-config --libs-only-L libcares | cut -c3-)
		INCDIR_ARES=$(shell pkg-config --cflags-only-I libcares | cut -c3-)
	endif
endif

ifeq ($(WITH_ARES),)
	ifneq ($(wildcard /lib$(LIBARCH)/libares$(SHLIB_EXT)* /usr/lib$(LIBARCH)/libares$(SHLIB_EXT)*),)
		ifneq ($(wildcard /usr/include/ares.h),)
			WITH_ARES=1
		endif
	endif
endif

ifeq ($(WITH_ARES),)
	ifneq ($(wildcard /usr/local/lib$(LIBARCH)/libares$(SHLIB_EXT)*),)
		ifneq ($(wildcard /usr/local/include/ares.h),)
			INCDIR_ARES=/usr/local/include
			LIBDIR_ARES=/usr/local/lib/$(LIBARCH)
			WITH_ARES=1
		endif
	endif
endif

ifeq ($(WITH_ARES),)
	ifneq ($(wildcard /usr/sfw/lib$(LIBARCH)/libares$(SHLIB_EXT)*),)
		ifneq ($(wildcard /usr/sfw/include/ares.h),)
			INCDIR_ARES=/usr/sfw/include
			LIBDIR_ARES=/usr/sfw/lib/$(LIBARCH)
			WITH_ARES=1
		endif
	endif
endif

ifeq ($(WITH_ARES),1)
	ifneq ($(INCDIR_ARES),)
		INC_ARES	= -I$(INCDIR_ARES)
	endif
	ifneq ($(LIBDIR_ARES),)
		LIB_DNS	= -L$(LIBDIR_ARES) $(LDOPT_R)$(LIBDIR_ARES)
	endif
	DEF += -DWITH_ARES -DWITH_DNS
	LIB_DNS	+= -lcares
	WITH_DNS=1
	FOUND += LIBC-ARES
else
	NOT_FOUND += LIBC-ARES
endif

# Check for lwres library if c-ares is unavailable:

ifeq ($(WITH_ARES),0)
	# Try pkg-config first:
	ifeq ($(WITH_LWRES),)
		ifeq ($(shell pkg-config --exists liblwres 2>/dev/null ; echo $$?),0)
			WITH_LWRES=1
			LIBDIR_LWRES=$(shell pkg-config --libs-only-L liblwres | cut -c3-)
			INCDIR_LWRES=$(shell pkg-config --cflags-only-I liblwres | cut -c3-)
		endif
	endif

	ifeq ($(WITH_LWRES),)
		ifneq ($(wildcard /lib$(LIBARCH)/liblwres$(SHLIB_EXT)* /usr/lib$(LIBARCH)/liblwres$(SHLIB_EXT)*),)
			ifneq ($(wildcard /usr/include/lwres),)
				WITH_LWRES=1
			endif
		endif
	endif

	ifeq ($(WITH_LWRES),)
		ifneq ($(wildcard /usr/local/lib$(LIBARCH)/liblwres$(SHLIB_EXT)*),)
			ifneq ($(wildcard /usr/local/include/lwres),)
				INCDIR_LWRES=/usr/local/include
				LIBDIR_LWRES=/usr/local/lib/$(LIBARCH)
				WITH_LWRES=1
			endif
		endif
	endif

	ifeq ($(WITH_LWRES),)
		ifneq ($(wildcard /usr/sfw/lib$(LIBARCH)/liblwres$(SHLIB_EXT)*),)
			ifneq ($(wildcard /usr/sfw/include/lwres),)
				INCDIR_LWRES=/usr/sfw/include
				LIBDIR_LWRES=/usr/sfw/lib/$(LIBARCH)
				WITH_LWRES=1
			endif
		endif
	endif

	ifeq ($(WITH_LWRES),1)
		ifneq ($(INCDIR_LWRES),)
			INC_LWRES	= -I$(INCDIR_LWRES)
		endif
		ifneq ($(LIBDIR_LWRES),)
			LIB_DNS	= -L$(LIBDIR_LWRES) $(LDOPT_R)$(LIBDIR_LWRES)
		endif
		DEF += -DWITH_LWRES -DWITH_DNS
		LIB_DNS	+= -llwres
		WITH_DNS=1
		FOUND += LIB-LWRES
	else
		ifeq ($(WITH_ARES),0)
			NOT_FOUND += LIB-LWRES
		endif
	endif
endif

# Check for OpenSSL library:

# Try pkg-config first:
ifeq ($(WITH_SSL),)
	ifeq ($(shell pkg-config --exists openssl 2>/dev/null ; echo $$?),0)
		WITH_SSL=1
		LIBDIR_SSL=$(shell pkg-config --libs-only-L openssl | cut -c3-)
		INCDIR_SSL=$(shell pkg-config --cflags-only-I openssl | cut -c3-)
	endif
endif

ifeq ($(WITH_SSL),)
	ifneq ($(wildcard /lib$(LIBARCH)/libcrypto$(SHLIB_EXT)* /usr/lib$(LIBARCH)/libcrypto$(SHLIB_EXT)*),)
		ifneq ($(wildcard /lib$(LIBARCH)/libssl$(SHLIB_EXT)* /usr/lib$(LIBARCH)/libssl$(SHLIB_EXT)*),)
			ifneq ($(wildcard /usr/include/openssl),)
				WITH_SSL=1
			endif
		endif
	endif
endif

ifeq ($(WITH_SSL),)
	ifneq ($(wildcard /usr/local/lib$(LIBARCH)/libcrypto$(SHLIB_EXT)*),)
		ifneq ($(wildcard /usr/local/lib$(LIBARCH)/libssl$(SHLIB_EXT)*),)
			ifneq ($(wildcard /usr/local/include/openssl),)
				INCDIR_SSL=/usr/local/include
				LIBDIR_SSL=/usr/local/lib$(LIBARCH)
				WITH_SSL=1
			endif
		endif
	endif
endif

ifeq ($(WITH_SSL),)
	ifneq ($(wildcard /usr/sfw/lib$(LIBARCH)/libcrypto$(SHLIB_EXT)*),)
		ifneq ($(wildcard /usr/sfw/lib$(LIBARCH)/libssl$(SHLIB_EXT)*),)
			ifneq ($(wildcard /usr/sfw/include/openssl),)
				INCDIR_SSL=/usr/sfw/include
				LIBDIR_SSL=/usr/sfw/lib$(LIBARCH)
				WITH_SSL=1
			endif
		endif
	endif
endif

ifeq ($(WITH_SSL),1)
	ifneq ($(INCDIR_SSL),)
		INC_SSL		= -I$(INCDIR_SSL)
	endif
	ifneq ($(LIBDIR_SSL),)
		LIB_SSL		= -L$(LIBDIR_SSL) $(LDOPT_R)$(LIBDIR_SSL)
		LIB_SSL_CRYPTO	= -L$(LIBDIR_SSL) $(LDOPT_R)$(LIBDIR_SSL)
	endif
	DEF += -DWITH_SSL
	LIB_SSL	+= -lssl -lcrypto
	LIB_SSL_CRYPTO	+= -lcrypto
	FOUND += LIB-SSL
else
	NOT_FOUND += LIB-SSL
endif

# Check for LibTLS library:

# Try pkg-config first:
ifeq ($(WITH_TLS),)
	ifeq ($(shell pkg-config --exists libtls 2>/dev/null ; echo $$?),0)
		WITH_TLS=1
		LIBDIR_TLS=$(shell pkg-config --libs-only-L libtls | cut -c3-)
		INCDIR_TLS=$(shell pkg-config --cflags-only-I libtls | cut -c3-)
	endif
endif

ifeq ($(WITH_TLS),)
	ifneq ($(wildcard /usr/lib$(LIBARCH)/libtls$(SHLIB_EXT)*),)
		ifneq ($(wildcard /lib$(LIBARCH)/libtls$(SHLIB_EXT)*)*),)
			ifneq ($(wildcard /usr/include/tls.h),)
				WITH_TLS=1
			endif
		endif
	endif
endif

ifeq ($(WITH_TLS),)
	ifneq ($(wildcard /usr/local/lib$(LIBARCH)/libtls$(SHLIB_EXT)*),)
		ifneq ($(wildcard /usr/local/include/tls.h),)
			INCDIR_TLS=/usr/local/include
			LIBDIR_TLS=/usr/local/lib$(LIBARCH)
			WITH_TLS=1
		endif
	endif
endif

ifeq ($(WITH_TLS),1)
	ifneq ($(INCDIR_TLS),)
		INC_TLS		= -I$(INCDIR_TLS)
	endif
	ifneq ($(LIBDIR_TLS),)
		LIB_TLS		= -L$(LIBDIR_TLS) $(LDOPT_R)$(LIBDIR_TLS)
		LIB_TLS_CRYPTO	= -L$(LIBDIR_TLS) $(LDOPT_R)$(LIBDIR_TLS)
	endif
	DEF += -DWITH_TLS
	LIB_TLS += -ltls
	FOUND += LIB_TLS
else
	NOT_FOUND += LIB_TLS
endif

ifneq ($(WITH_PCRE),1)
	# Try to auto-detect PCRE v2

	# Try pkg-config first:
	ifeq ($(WITH_PCRE2),)
		ifeq ($(shell pkg-config --exists libpcre2-8 2>/dev/null ; echo $$?),0)
			WITH_PCRE2=1
			LIBDIR_PCRE2=$(shell pkg-config --libs-only-L libpcre2-8 | cut -c3-)
			INCDIR_PCRE2=$(shell pkg-config --cflags-only-I libpcre2-8 | cut -c3-)
		endif
	endif

	ifeq ($(WITH_PCRE2),)
		ifneq ($(wildcard /lib$(LIBARCH)/libpcre2-8$(SHLIB_EXT)* /usr/lib$(LIBARCH)/libpcre2-8$(SHLIB_EXT)* "/usr/lib/*/libpcre2-8$(SHLIB_EXT)*",)
			ifneq ($(wildcard /usr/include/pcre2.h),)
				WITH_PCRE2=1
			endif
		endif
	endif

	ifeq ($(WITH_PCRE2),)
		ifneq ($(wildcard /usr/local/lib$(LIBARCH)/libpcre2-8$(SHLIB_EXT)*),)
			ifneq ($(wildcard /usr/local/include/pcre2.h),)
				INCDIR_PCRE2=/usr/local/include
				LIBDIR_PCRE2=/usr/local/lib$(LIBARCH)
				WITH_PCRE2=1
			endif
		endif
	endif

	ifeq ($(WITH_PCRE2),)
		ifneq ($(wildcard /opt/local/lib$(LIBARCH)/libpcre2-8$(SHLIB_EXT)*),)
			ifneq ($(wildcard /opt/local/include/pcre2.h),)
				INCDIR_PCRE2=/opt/local/include
				LIBDIR_PCRE2=/opt/local/lib$(LIBARCH)
				WITH_PCRE2=1
			endif
		endif
	endif

	ifeq ($(WITH_PCRE2),)
		ifneq ($(wildcard /usr/sfw/lib$(LIBARCH)/libpcre2-8$(SHLIB_EXT)*),)
			ifneq ($(wildcard /usr/sfw/include/pcre2.h),)
				INCDIR_PCRE2=/usr/sfw/include
				LIBDIR_PCRE2=/usr/sfw/lib$(LIBARCH)
				WITH_PCRE2=1
			endif
		endif
	endif
endif

ifeq ($(WITH_PCRE2),1)
	ifneq ($(INCDIR_PCRE2),)
		INC_PCRE	= -I$(INCDIR_PCRE2)
	endif
	ifneq ($(LIBDIR_PCRE2),)
		LIB_PCRE	= -L$(LIBDIR_PCRE2) $(LDOPT_R)$(LIBDIR_PCRE2)
	endif
	DEF += -DWITH_PCRE2 -DPCRE2_CODE_UNIT_WIDTH=8
	LIB_PCRE	+= -lpcre2-8
	FOUND += LIB-PCRE2
endif

ifeq ($(WITH_PCRE2),1)
	WITH_PCRE=0
endif

ifneq ($(WITH_PCRE2),1)
	# Try to auto-detect PCRE unless configure told us to use v2

	# Try pkg-config first:
	ifeq ($(WITH_PCRE),)
		ifeq ($(shell pkg-config --exists libpcre 2>/dev/null ; echo $$?),0)
			WITH_PCRE=1
			LIBDIR_PCRE=$(shell pkg-config --libs-only-L libpcre | cut -c3-)
			INCDIR_PCRE=$(shell pkg-config --cflags-only-I libpcre | cut -c3-)
		endif
	endif

	ifeq ($(WITH_PCRE),)
		ifneq ($(wildcard /lib$(LIBARCH)/libpcre$(SHLIB_EXT)* /usr/lib$(LIBARCH)/libpcre$(SHLIB_EXT)* /usr/lib/*/libpcre$(SHLIB_EXT)*),)
			ifneq ($(wildcard /usr/include/pcre.h),)
				WITH_PCRE=1
			endif
		endif
	endif

	ifeq ($(WITH_PCRE),)
		ifneq ($(wildcard /usr/local/lib$(LIBARCH)/libpcre$(SHLIB_EXT)*),)
			ifneq ($(wildcard /usr/local/include/pcre.h),)
				INCDIR_PCRE=/usr/local/include
				LIBDIR_PCRE=/usr/local/lib$(LIBARCH)
				WITH_PCRE=1
			endif
		endif
	endif

	ifeq ($(WITH_PCRE),)
		ifneq ($(wildcard /opt/local/lib$(LIBARCH)/libpcre$(SHLIB_EXT)*),)
			ifneq ($(wildcard /opt/local/include/pcre.h),)
				INCDIR_PCRE=/opt/local/include
				LIBDIR_PCRE=/opt/local/lib$(LIBARCH)
				WITH_PCRE=1
			endif
		endif
	endif

	ifeq ($(WITH_PCRE),)
		ifneq ($(wildcard /usr/sfw/lib$(LIBARCH)/libpcre$(SHLIB_EXT)*),)
			ifneq ($(wildcard /usr/sfw/include/pcre.h),)
				INCDIR_PCRE=/usr/sfw/include
				LIBDIR_PCRE=/usr/sfw/lib$(LIBARCH)
				WITH_PCRE=1
			endif
		endif
	endif
endif

ifeq ($(WITH_PCRE),1)
	ifneq ($(INCDIR_PCRE),)
		INC_PCRE	= -I$(INCDIR_PCRE)
	endif
	ifneq ($(LIBDIR_PCRE),)
		LIB_PCRE	= -L$(LIBDIR_PCRE) $(LDOPT_R)$(LIBDIR_PCRE)
	endif
	DEF += -DWITH_PCRE
	LIB_PCRE	+= -lpcre
	FOUND += LIB_PCRE
else
	ifeq ($(WITH_PCRE),1)
		# NOT_FOUND += LIB_PCRE
		NOT_FOUND += LIB_PCRE2
	endif
endif

# Check for FreeRADIUS client library:

# Try pkg-config first:
ifeq ($(WITH_FREERADIUS),)
	ifeq ($(shell pkg-config --exists libfreeradius-client 2>/dev/null ; echo $$?),0)
		WITH_FREERADIUS=1
		LIBDIR_FREERADIUS=$(shell pkg-config --libs-only-L libfreeradius-client | cut -c3-)
		INCDIR_FREERADIUS=$(shell pkg-config --cflags-only-I libfreeradius-client | cut -c3-)
	endif
endif

ifeq ($(WITH_FREERADIUS),)
	ifneq ($(wildcard /lib$(LIBARCH)/libfreeradius-client$(SHLIB_EXT)* /usr/lib$(LIBARCH)/libfreeradius-client$(SHLIB_EXT)*),)
		ifneq ($(wildcard /usr/include/freeradius-client.h),)
			WITH_FREERADIUS=1
		endif
	endif
endif

ifeq ($(WITH_FREERADIUS),)
	ifneq ($(wildcard /usr/local/lib$(LIBARCH)/libfreeradius-client$(SHLIB_EXT)*),)
		ifneq ($(wildcard /usr/local/include/freeradius-client.h),)
			INCDIR_FREERADIUS=/usr/local/include
			LIBDIR_FREERADIUS=/usr/local/lib$(LIBARCH)
			WITH_FREERADIUS=1
		endif
	endif
endif

ifeq ($(WITH_FREERADIUS),)
	ifneq ($(wildcard /usr/sfw/lib$(LIBARCH)/libfreeradius-client$(SHLIB_EXT)*),)
		ifneq ($(wildcard /usr/sfw/include/freeradius-client.h),)
			INCDIR_FREERADIUS=/usr/sfw/include
			LIBDIR_FREERADIUS=/usr/sfw/lib$(LIBARCH)
			WITH_FREERADIUS=1
		endif
	endif
endif

ifeq ($(WITH_FREERADIUS),1)
	ifneq ($(INCDIR_FREERADIUS),)
		INC_FREERADIUS	= -I$(INCDIR_FREERADIUS)
	endif
	ifneq ($(LIBDIR_FREERADIUS),)
		LIB_FREERADIUS	= -L$(LIBDIR_FREERADIUS) $(LDOPT_R)$(LIBDIR_FREERADIUS)
	endif
	LIB_FREERADIUS	+= -lfreeradius-client
	FOUND += LIB-FREERADIUS
endif

# Check for RADCLI library:

# Try pkg-config first:
ifeq ($(WITH_LIBRADCLI),)
	ifeq ($(shell pkg-config --exists radcli 2>/dev/null ; echo $$?),0)
		WITH_LIBRADCLI=1
		LIBDIR_LIBRADCLI=$(shell pkg-config --libs-only-L radcli | cut -c3-)
		INCDIR_LIBRADCLI=$(shell pkg-config --cflags-only-I radcli | cut -c3-)
	endif
endif

ifeq ($(WITH_LIBRADCLI),)
	ifneq ($(wildcard /lib$(LIBARCH)/libradcli$(SHLIB_EXT)* /usr/lib$(LIBARCH)/libradcli(SHLIB_EXT)*) /usr/lib/*/libradcli$(SHLIB_EXT)*),)
		ifneq ($(wildcard /usr/include/radcli/radcli.h),)
			WITH_LIBRADCLI=1
		endif
	endif
endif

ifeq ($(WITH_LIBRADCLI),)
	ifneq ($(wildcard /usr/local/lib$(LIBARCH)/libradcli$(SHLIB_EXT)*),)
		ifneq ($(wildcard /usr/local/include/radcli/radcli.h),)
			INCDIR_LIBRADCLI=/usr/local/include
			LIBDIR_LIBRADCLI=/usr/local/lib$(LIBARCH)
			WITH_LIBRADCLI=1
		endif
	endif
endif

ifeq ($(WITH_LIBRADCLI),1)
	ifneq ($(INCDIR_LIBRADCLI),)
		INC_LIBRADCLI	= -I$(INCDIR_LIBRADCLI)
	endif
	ifneq ($(LIBDIR_LIBRADCLI),)
		LIB_LIBRADCLI	= -L$(LIBDIR_LIBRADCLI) $(LDOPT_R)$(LIBDIR_LIBRADCLI)
	endif
	LIB_LIBRADCLI	+= -lradcli
	DEF += -DWITH_LIBRADCLI
	FOUND += LIB-RADCLI
else
	NOT_FOUND += LIB-FREERADIUS-CLIENT
	NOT_FOUND += LIB-RADCLI
endif

# Check for ZLIB library:

# Try pkg-config first:
ifeq ($(WITH_ZLIB),)
	ifeq ($(shell pkg-config --exists libz 2>/dev/null ; echo $$?),0)
		WITH_ZLIB=1
		LIBDIR_ZLIB=$(shell pkg-config --libs-only-L libz | cut -c3-)
		INCDIR_ZLIB=$(shell pkg-config --cflags-only-I libz | cut -c3-)
	endif
endif

ifeq ($(WITH_ZLIB),)
	ifneq ($(wildcard /usr/include/zlib.h),)
		WITH_ZLIB=1
	endif
endif

ifeq ($(WITH_ZLIB),)
	ifneq ($(wildcard /usr/local/include/zlib.h),)
		INCDIR_ZLIB=/usr/local/include
		LIBDIR_ZLIB=/usr/local/lib$(LIBARCH)
		WITH_ZLIB=1
	endif
endif

ifeq ($(WITH_ZLIB),1)
	ifneq ($(INCDIR_ZLIB),)
		INC_ZLIB	= -I$(INCDIR_ZLIB)
	endif
	ifneq ($(LIBDIR_ZLIB),)
		LIB_ZLIB	= -L$(LIBDIR_ZLIB) $(LDOPT_R)$(LIBDIR_ZLIB)
	endif
	DEF += -DWITH_ZLIB
	LIB_ZLIB	+= -lz
	FOUND += LIB-ZLIB
else
	NOT_FOUND += LIB-ZLIB
endif

# Check for execinfo:

# Try pkg-config first:
ifeq ($(WITH_EXECINFO),)
	ifeq ($(shell pkg-config --exists libexecinfo 2>/dev/null ; echo $$?),0)
		WITH_EXECINFO=$(
		LIB_EXECINFO += $(shell pkg-config --libs-only-l libexecinfo)
		LIBDIR_EXECINFO=$(shell pkg-config --libs-only-L libexecinfo | cut -c3-)
		INCDIR_EXECINFO=$(shell pkg-config --cflags-only-I libexecinfo | cut -c3-)
	endif
endif

ifeq ($(WITH_EXECINFO),)
	ifneq ($(wildcard /usr/include/execinfo.h),)
		WITH_EXECINFO=1
	endif
	ifneq ($(wildcard /usr/lib/libexecinfo$(SHLIB_EXT)*),)
		LIB_EXECINFO	+= -lexecinfo
	endif
endif

ifeq ($(WITH_EXECINFO),)
	ifneq ($(wildcard /usr/local/lib/libexecinfo$(SHLIB_EXT)*),)
		ifneq ($(wildcard /usr/local/include/execinfo.h),)
			WITH_EXECINFO=1
			LIB_EXECINFO	+= -lexecinfo
			INCDIR_EXECINFO=/usr/local/include
			LIBDIR_EXECINFO=/usr/local/lib
		endif
	endif
endif

ifeq ($(WITH_EXECINFO),1)
	ifneq ($(INCDIR_EXECINFO),)
		INC_EXECINFO	= -I$(INCDIR_EXECINFO)
	endif
	ifneq ($(LIBDIR_EXECINFO),)
		LIB_EXECINFO	= -L$(LIBDIR_EXECINFO) $(LDOPT_R)$(LIBDIR_EXECINFO)
		LIB_EXECINFO	+= -lexecinfo
	endif
	DEF += -DHAVE_EXECINFO_H
endif

# Check for crypt library:

ifeq ($(HAS_LIBCRYPT),)
	# check standard locations
	ifneq ($(wildcard /lib$(LIBARCH)/libcrypt$(SHLIB_EXT)* /usr/lib$(LIBARCH)/libcrypt$(SHLIB_EXT)* /lib$(LIBARCH)/*/libcrypt$(SHLIB_EXT)*),)
		HAS_LIBCRYPT=1
	endif
	# evaluate ld search path
	ifeq ($(HAS_LIBCRYPT),)
		LDSD := $(shell ld --verbose 2>/dev/null | grep SEARCH_DIR | sed "s/SEARCH_DIR(\"=/ /g" | sed 's/");/\/libcrypt.so/g')
		ifneq ($(wildcard $(LDSD)),)
			HAS_LIBCRYPT=1
		endif
	endif
endif

ifeq ($(HAS_LIBCRYPT),1)
	LIBCRYPT	= -lcrypt
	DEF += -DWITH_LIBCRYPT
endif

# Check for IPC:

ifeq ($(WITH_IPC),)
	ifneq ($(wildcard /usr/include/sys/ipc.h),)
		WITH_IPC=1
	endif
endif

# Check for CURL:

# Try pkg-config first:
ifeq ($(WITH_CURL),)
	ifeq ($(shell pkg-config --exists libcurl 2>/dev/null ; echo $$?),0)
		WITH_CURL=1
		LIB_CURL += $(shell pkg-config --libs-only-l libcurl)
		LIBDIR_CURL=$(shell pkg-config --libs-only-L libcurl | cut -c3-)
		INCDIR_CURL=$(shell pkg-config --cflags-only-I libcurl | cut -c3-)
	endif
endif

ifeq ($(WITH_CURL),)
	ifneq ($(wildcard /usr/lib$(LIBARCH)/libcurl$(SHLIB_EXT)*),)
		ifneq ($(wildcard /usr/include/curl),)
			WITH_CURL=1
		endif
	endif
endif

ifeq ($(WITH_CURL),)
	ifneq ($(wildcard /usr/local/lib/libcurl$(SHLIB_EXT)*),)
		ifneq ($(wildcard /usr/local/include/curl),)
			INCDIR_CURL=/usr/local/include
			LIBDIR_CURL=/usr/local/lib
			WITH_CURL=1
		endif
	endif
endif

ifeq ($(WITH_CURL),)
	# NetBSD, possibly
	ifneq ($(wildcard /usr/pkg/lib/libcurl$(SHLIB_EXT)*),)
		ifneq ($(wildcard /usr/pkg/include/curl),)
			INCDIR_CURL=/usr/pkg/include
			LIBDIR_CURL=/usr/pkg/lib
			WITH_CURL=1
		endif
	endif
endif

ifeq ($(WITH_CURL),1)
	ifneq ($(INCDIR_CURL),)
		INC_CURL	= -I$(INCDIR_CURL)
	endif
	ifneq ($(LIBDIR_CURL),)
		LIB_CURL	= -L$(LIBDIR_CURL) $(LDOPT_R)$(LIBDIR_CURL)
	endif
	LIB_CURL	+= -lcurl
	FOUND += LIB-CURL
else
	NOT_FOUND += LIB-CURL
endif

# Check for PAM:

ifeq ($(WITH_PAM),)
	# NetBSD
	ifneq ($(wildcard /usr/pkg/lib/libpam$(SHLIB_EXT)*),)
		ifneq ($(wildcard /usr/pkg/include/pam),)
			INCDIR_PAM=/usr/pkg/include
			LIBDIR_PAM=/usr/pkg/lib
			WITH_PAM=1
		endif
	endif
endif

ifeq ($(WITH_PAM),)
	ifneq ($(wildcard /usr/include/security/pam_appl.h),)
		WITH_PAM=1
	endif
endif

ifeq ($(WITH_PAM),)
	ifneq ($(wildcard /usr/lib$(LIBARCH)/libpam$(SHLIB_EXT)*),)
		ifneq ($(wildcard /usr/include/pam),)
			WITH_PAM=1
		endif
	endif
endif

ifeq ($(WITH_PAM),1)
	ifneq ($(wildcard /usr/include/security/pam_appl.h),)
		DEF += -DHAVE_SECURITY_PAM_APPL_H
	endif
	ifneq ($(INCDIR_PAM),)
		INC_PAM	= -I$(INCDIR_PAM)
	endif
	ifneq ($(LIBDIR_PAM),)
		LIB_PAM	= -L$(LIBDIR_PAM) $(LDOPT_R)$(LIBDIR_PAM)
	endif
	LIB_PAM	+= -lpam
	FOUND += LIB-PAM
else
	NOT_FOUND += LIB-PAM
endif

# Check for SCTP:

ifeq ($(WITH_SCTP),)
	ifneq ($(wildcard /usr/include/netinet/sctp.h),)
		WITH_SCTP=1
	endif
endif

ifeq ($(WITH_SCTP),1)
	ifneq ($(wildcard /lib$(LIBARCH)/libsctp$(SHLIB_EXT)* /usr/lib$(LIBARCH)/libsctp$(SHLIB_EXT)*),)
		LIBSCTP=-lsctp
	endif
	DEF += -DWITH_SCTP
endif

ifeq ($(OSTYPE), linux)
	LIB_DL	= -ldl
endif
	
ifeq ($(OSTYPE), sunos)
	LIB_DL	= -ldl
	ifeq ($(WITH_PORT),)
		ifneq ($(wildcard /usr/include/port.h),)
			WITH_PORT=1
		endif
	endif
	ifeq ($(WITH_DEVPOLL),)
		# Deprecated by Sun, and rightfully so.
		ifneq ($(wildcard /usr/include/sys/devpoll.h),)
			WITH_DEVPOLL=1
		endif
	endif
endif

ifeq ($(wildcard /usr/include/sys),)
		USRINCLUDESYS=/usr/include/$(shell uname -m)-linux-gnu/sys
else
		USRINCLUDESYS=/usr/include/sys
endif

ifeq ($(WITH_EPOLL),)
	ifneq ($(wildcard $(USRINCLUDESYS)/epoll.h),)
		WITH_EPOLL=1
	endif
endif

ifeq ($(WITH_KQUEUE),)
	ifneq ($(wildcard /usr/include/sys/event.h),)
		WITH_KQUEUE=1
	endif
endif

ifeq ($(WITH_POLL),)
	ifneq ($(wildcard $(USRINCLUDESYS)/poll.h),)
		WITH_POLL=1
	endif
endif

ifeq ($(WITH_SELECT),)
	ifneq ($(wildcard $(USRINCLUDESYS)/select.h),)
		WITH_SELECT=1
	endif
endif

ifeq ($(WITH_PORT)$(WITH_DEVPOLL)$(WITH_EPOLL)$(WITH_KQUEUE)$(WITH_POLL)$(WITH_SELECT),)
$(error None of the supported event polling mechanisms seems to be available on your system. Check your installation, some include files may be missing.)
endif

ifeq ($(WITH_PORT),1)
	DEF += -DWITH_PORT
endif

ifeq ($(WITH_DEVPOLL),1)
	DEF += -DWITH_DEVPOLL
endif

ifeq ($(WITH_EPOLL),1)
	DEF += -DWITH_EPOLL
endif

ifeq ($(WITH_KQUEUE),1)
	DEF += -DWITH_KQUEUE
endif

ifeq ($(WITH_POLL),1)
	DEF += -DWITH_POLL
endif

ifeq ($(WITH_SELECT),1)
	DEF += -DWITH_SELECT
endif

ifeq ($(WITH_CURL),1)
	DEF += -DWITH_CURL
endif

ifeq ($(WITH_IPC),1)
	DEF += -DWITH_IPC
endif

ifneq ($(NOT_FOUND),)
	ifeq ($(MAKELEVEL),0)
$(warning Development files not found for $(NOT_FOUND).)
	endif
endif

%:: %,v

%:: RCS/%,v

%:: RCS/%

%:: SCCS/%

%:: %.c

%:: %.pl

%.o: %.c $(DIR_MAVIS)/token.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

%:: %.h

endif


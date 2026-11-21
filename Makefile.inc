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
GITBRANCH	:= $(shell git branch --show-current 2>/dev/null)
GITBRANCH_EXT :=
ifneq ($(GITBRANCH),)
  GITBRANCH_EXT := -$(GITBRANCH)
endif

MF_OBJ=build/Makefile.inc.$(OS)$(GITBRANCH_EXT)
ifeq ($(wildcard $(MF_OBJ)),)
	MF_OBJ=../build/Makefile.inc.$(OS)$(GITBRANCH_EXT)
	ifeq ($(wildcard $(MF_OBJ)),)
		MF_OBJ=../../build/Makefile.inc.$(OS)$(GITBRANCH_EXT)
		ifeq ($(wildcard $(MF_OBJ)),)
			MF_OBJ=../../../build/Makefile.inc.$(OS)$(GITBRANCH_EXT)
			ifeq ($(wildcard $(MF_OBJ)),)
$(error Please run the configure script to create Makefile.inc.$(OS))$(GITBRANCH_EXT)
			endif
		endif
	endif
endif

include $(MF_OBJ)

%:: %,v

%:: RCS/%,v

%:: RCS/%

%:: SCCS/%

%:: %.c

%:: %.pl

CFLAGS := -I$(BASE)/build/$(OS)$(GITBRANCH_EXT)/mavis -I$(BASE)/build/$(OS)$(GITBRANCH_EXT) $(CFLAGS)

%.o: %.c $(BASE)/build/$(OS)$(GITBRANCH_EXT)/mavis/token.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

%:: %.h

endif


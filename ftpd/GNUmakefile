# top level Makefile for ftpd
# (C) 1997-2001 Marc Huber <Marc.Huber@web.de>
#
# requires GNU make

include ../Makefile.inc
PROG	= ftpd
OD	= $(BASE)/build/$(OS)/$(PROG)

all: build

$(OD):
	@mkdir -p $@

extra/Makefile: ../Makefile
	@cp $^ $@

env: $(OD) extra/Makefile

extra_build:
	@$(MAKE) -C extra BASE=$(BASE)

build:	env extra_build messages.c
	@$(MAKE) -f $(BASE)/$(PROG)/Makefile.obj -C "$(OD)" BASE=$(BASE)

messages.c: nls/messages.txt
	@cd nls && ./mknls.pl

install: build
	@$(MAKE) -f $(BASE)/$(PROG)/Makefile.obj -C "$(OD)" BASE=$(BASE) install

clean:
	@rm -rf "$(OD)" *~ core *.BAK


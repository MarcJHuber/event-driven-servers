# top level Makefile for spawnd
# (C) 1997-2011 Marc Huber <Marc.Huber@web.de>
#
# requires GNU make

include ../Makefile.inc
PROG	= spawnd
OD	= $(BASE)/build/$(OS)/$(PROG)

all: build

$(OD):
	@mkdir -p $@

env: $(OD)

build:	env
	@$(MAKE) -f $(BASE)/$(PROG)/Makefile.obj -C "$(OD)" BASE=$(BASE)

install: build
	@$(MAKE) -f $(BASE)/$(PROG)/Makefile.obj -C "$(OD)" BASE=$(BASE) install

clean:
	@rm -rf "$(OD)" *~ core *.BAK 


# top level Makefile for mavisd
# (C) 1997-2011 Marc Huber <Marc.Huber@web.de>
#
# requires GNU make

include ../Makefile.inc
PROG	= mavisd
OD	= $(BASE)/build/$(OS)/$(PROG)

all: build

$(OD):
	@mkdir -p $@

extra/Makefile: ../Makefile
	@cp $^ $@

env: $(OD)

build:	env
	@$(MAKE) -f $(BASE)/$(PROG)/Makefile.obj -C "$(OD)" BASE=$(BASE)

install: build
	@$(MAKE) -f $(BASE)/$(PROG)/Makefile.obj -C "$(OD)" BASE=$(BASE) install

clean:
	@rm -rf "$(OD)" *~ core *.BAK 

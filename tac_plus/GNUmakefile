# top level Makefile for tac_plus
# (C) 1997-2011 Marc Huber <Marc.Huber@web.de>
#
# requires GNU make

include ../Makefile.inc
PROG	= tac_plus
OD	= $(BASE)/build/$(OS)/$(PROG)

all: build

$(OD):
	@mkdir -p $@

extra/Makefile: ../Makefile
	@cp $^ $@

env: $(OD) extra/Makefile

extra_build:
	@$(MAKE) -C extra BASE=$(BASE)

build:	env extra_build
	@$(MAKE) -f $(BASE)/$(PROG)/Makefile.obj -C "$(OD)" BASE=$(BASE)

install: build
	@$(MAKE) -f $(BASE)/$(PROG)/Makefile.obj -C "$(OD)" BASE=$(BASE) install

clean:
	@rm -rf "$(OD)" *~ core *.BAK


# top level Makefile for tactester
# (C)2025 Marc Huber <Marc.Huber@web.de>
#
# requires GNU make

include ../Makefile.inc
PROG	= tactester
OD	= $(BASE)/build/$(OS)/$(PROG)

all: build

$(OD):
	@mkdir -p $@

env: $(OD)

build:	env
	@$(MAKE) -f $(BASE)/$(PROG)/Makefile.obj -C "$(OD)" BASE=$(BASE)

install:
	@$(MAKE) -f $(BASE)/$(PROG)/Makefile.obj -C "$(OD)" BASE=$(BASE) install

clean:
	@rm -rf "$(OD)" *~ core *.BAK


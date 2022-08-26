# top level Makefile for mavis
# (C) 1997-2011 Marc Huber <Marc.Huber@web.de>
#
# requires GNU make

include ../Makefile.inc
PROG	= mavis
OD	= $(BASE)/build/$(OS)/$(PROG)

all: token.h build perl_build

$(OD):
	@mkdir -p "$@"

token.h: $(BASE)/mavis/token.pl
	@perl "$^"

env: $(OD)

build:	env
	@$(MAKE) -f "$(BASE)/$(PROG)/Makefile.obj" -C "$(OD)" "BASE=$(BASE)"

install: perl_install
	@$(MAKE) -f "$(BASE)/$(PROG)/Makefile.obj" -C "$(OD)" "BASE=$(BASE)" install

clean:
	@rm -rf "$(OD)" *~ core *.BAK

perl_build:
	@$(MAKE) -C perl "BASE=$(BASE)"

perl_install:
	@$(MAKE) -C perl "BASE=$(BASE)" install


#
# This makefile requires GNU make.
#

TR	= /usr/bin/tr

ifneq ($(wildcard /usr/xpg4/bin/tr),)
	TR	= /usr/xpg4/bin/tr
endif

OSs	:= $(shell uname -s | env -i $(TR) "[:upper:]/ " "[:lower:]--")
OSr	:= $(shell uname -r | sed "s/(.*)//" | env -i $(TR) "[:upper:]/ " "[:lower:]--")
OSm	:= $(shell uname -m | env -i $(TR) "[:upper:]/ " "[:lower:]--")
OS	:= $(OSs)-$(OSr)-$(OSm)

all: misc/version.h dirs install_fakeroot_doc

misc/version.h: LAST_COMMIT
	@set `cat $<` && printf "#define VERSION \"$$1\"\n" > $@

build:
	mkdir -p -m 0755 $@

ifneq ($(wildcard build/Makefile.inc.$(OS)),)
include Makefile.inc

install_fakeroot_doc:
	@$(MAKE) -r BASE=$(BASE) INSTALLROOT=$(BASE)/build/$(OS)/fakeroot install_doc

dirs:
	@for D in $(DIRS) ; do $(MAKE) -r -C $$D BASE=$(BASE) || exit 1; done

install: install_doc
	@for D in $(DIRS) ; do $(MAKE) -r -C $$D BASE=$(BASE) install || exit 1; done

$(INSTALLROOT)$(DOCDIR_DEST)/railroad: $(BASE)/doc/railroad
	@mkdir -p -m 0755 $@; for D in $(DIRS) ; do mkdir -p -m 0755 $@/$$D ; $(INSTALL) -m 0644 $</$$D/* $@/$$D ; done

$(INSTALLROOT)$(DOCDIR_DEST): $(BASE)/doc $(INSTALLROOT)$(DOCDIR_DEST)/railroad
	@test -f $</mavis.html && mkdir -p -m 0755 $@ && $(INSTALL) -m 0644 $</*.* $@ ; exit 0

install_doc: $(INSTALLROOT)$(DOCDIR_DEST) $(INSTALLROOT)$(DOCDIR_DEST)/railroad

else

build/Makefile.inc.$(OS): build configure
	./configure

dirs: build/Makefile.inc.$(OS)
	@$(MAKE) -r $@

install: dirs
	@$(MAKE) -r $@

install_fakeroot_doc: dirs
	@$(MAKE) -r $@

endif

clean:
	@-rm -rf build/$(OS) */Makefile */*/Makefile

distclean: clean
	@rm -rf *~ */*~ */*/*~ build ; mkdir -m 0755 build

tidy:
	@-rm -rf build */Makefile */*/Makefile *~ */*~ */*/*~
 



include ../../Makefile.inc

all: mavis.py

mavis.py: ../mavis.h mk_Mavis.pl
	perl mk_Mavis.pl > $@

M = $(INSTALLROOT)$(LIBDIR_DEST)/mavis
ME = $(M)/extra

$(M)/mavis.py: mavis.py
	perl $(BASE)/scripts/install_ascii.pl -R "# REMOVE #" -b -m 0644 $^ $@

$(M):
	@mkdir -p -m 0755 $@

$(ME):
	@mkdir -p -m 0755 $@


install: $(M) $(M)/mavis.py

install: $(M) $(ME) $(BI) $(M)/Mavis.pm $(EI)

install_stage:
	@$(MAKE) INSTALLROOT=$(BASE)/build/$(OS)/fakeroot install



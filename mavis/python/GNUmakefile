include ../../Makefile.inc

P=mavis.py
SUF=py

all: $(P)

$(P): ../mavis.h mk_Mavis.pl
	perl mk_Mavis.pl > $@

M = $(INSTALLROOT)$(LIBDIR_DEST)/mavis
ME = $(M)/extra

BACKENDS =	tacplus_demo tacplus_ldap

BI = $(patsubst %,$(M)/mavis_%.$(SUF), $(BACKENDS))

$(BI): $(M)/%.$(SUF): %.$(SUF)
	perl $(BASE)/scripts/install_ascii.pl -R "# REMOVE #" -b -S "s#${M}#${LIBDIR_DEST}/mavis#g" -S "s#/usr/local/lib/mavis#${LIBDIR_DEST}/mavis#g" -m 0755 $^ $@

$(M)/$(P): $(P)
	perl $(BASE)/scripts/install_ascii.pl -R "# REMOVE #" -b -m 0644 $^ $@

$(M):
	@mkdir -p -m 0755 $@

$(ME):
	@mkdir -p -m 0755 $@

install: $(M) $(ME) $(BI) $(M)/$(P)
	@python3 --version >/dev/null 2>/dev/null || exit 0; python3 -m compileall $(M)

install_stage:
	@$(MAKE) INSTALLROOT=$(BASE)/build/$(OS)/fakeroot install


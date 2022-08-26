include ../../Makefile.inc

all: Mavis.pm

Mavis.pm: ../mavis.h mk_Mavis.pl
	perl mk_Mavis.pl > $@

M = $(INSTALLROOT)$(LIBDIR_DEST)/mavis
ME = $(M)/extra

BACKENDS =	ftp_passwd ldap_authonly tacplus_ads tacplus_ldap
BACKENDS +=	tacplus_ldap_authonly tacplus_opie tacplus_passwd
BACKENDS +=	tacplus_radius tacplus_sms tacplus_shadow

BI = $(patsubst %,$(M)/mavis_%.pl, $(BACKENDS))

$(BI): $(M)/%.pl: %.pl
	perl $(BASE)/scripts/install_ascii.pl -R "# REMOVE #" -b -S "s#${M}#${LIBDIR_DEST}/mavis#g" -S "s#/usr/local/lib/mavis#${LIBDIR_DEST}/mavis#g" -m 0755 $^ $@

$(M)/Mavis.pm: Mavis.pm
	perl $(BASE)/scripts/install_ascii.pl -R "# REMOVE #" -b -m 0644 $^ $@

$(M):
	@mkdir -p -m 0755 $@

$(ME):
	@mkdir -p -m 0755 $@

EXTRA =	tacacs.schema tacacs.schema-fedora-ds tacacs_schema.ldif

EI = $(patsubst %,$(ME)/%, $(EXTRA))

$(EI): $(ME)/%: %
	perl $(BASE)/scripts/install_ascii.pl -R "# REMOVE #" -b -m 0644 $^ $@

install: $(M) $(ME) $(BI) $(M)/Mavis.pm $(EI)

install_stage:
	@$(MAKE) INSTALLROOT=$(BASE)/build/$(OS)/fakeroot install


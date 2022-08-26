include $(BASE)/Makefile.inc

S = etc_init.d_tac_plus
E = $(INSTALLROOT)$(LIBARCHDIR_DEST)/mavis/extra

all: $(S)

$(S): ../../spawnd/extra/etc_init.d_spawnd
	-sed 's/spawnd/tac_plus/g'< $^ > $@

$(E)/$(S): $(S)
	$(INSTALL) -m 0755 $^ $@

$(E):
	@mkdir -p -m 0755 $@

$(E)/de.pro-bono-publico.tac_plus.plist: de.pro-bono-publico.tac_plus.plist
	$(INSTALL) -m 0644 $^ $@

$(E)/tac_plus.cfg-ads: tac_plus.cfg-ads
	$(INSTALL) -m 0644 $^ $@

$(E)/tac_plus.service: tac_plus.service
	$(INSTALL) -m 0644 $^ $@

$(INSTALLROOT)$(SBINDIR_DEST)/tacspooflog.pl: tacspooflog.pl
	$(INSTALL) -m 0755 $^ $@

install: $(E) $(E)/$(S) $(E)/de.pro-bono-publico.tac_plus.plist $(E)/etc_init.d_tac_plus $(E)/tac_plus.cfg-ads $(E)/tac_plus.service $(INSTALLROOT)$(SBINDIR_DEST)/tacspooflog.pl


SUBDIRS = intl m4 man po 

bin_PROGRAMS = couriergrey

noinst_HEADERS = couriergrey.h database.h mail_processor.h message_processor.h timestore.h whitelist.h

sysconf_DATA = whitelist_ip.dist

couriergrey_SOURCES = couriergrey.cc database.cc mail_processor.cc message_processor.cc timestore.cc whitelist.cc

couriergrey_LDFLAGS = @LDFLAGS@

ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = config.rpath whitelist_ip.dist README.md

DEFS = -DLOCALEDIR=\"$(localedir)\" @DEFS@

install-data-hook:
	@list='$(sysconf_DATA)'; for p in $$list; do \
	    dest=`echo $$p | sed -e s/.dist//`; \
	    if test -f $(DESTDIR)$(sysconfdir)/$$dest; then \
		echo "$@ will not overwrite existing $(DESTDIR)$(sysconfdir)/$$dest"; \
	    else \
		echo " $(INSTALL_DATA) $$p $(DESTDIR)$(sysconfdir)/$$dest"; \
		$(INSTALL_DATA) $$p $(DESTDIR)$(sysconfdir)/$$dest; \
	    fi; \
	done

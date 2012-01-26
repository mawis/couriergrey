man_MANS = couriergrey.8
EXTRA_DIST = couriergrey.8.in

edit = sed \
       -e 's,\@VERSION\@,$(VERSION),g'

$(man_MANS):
	@echo "generating $@ from $@.in"; \
	    edit='$(edit)'; \
	    rm -f $@ $@.tmp; \
	    eval "$$edit < $@.in > $@.tmp"; \
	    mv $@.tmp $@

clean-local:
	rm -f $(man_MANS)

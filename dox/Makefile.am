doxdatadir = $(datadir)/$(PACKAGE)-doc

all: html-local
 
html-local:
if DOXY_DOC
	rm -rf html/
	$(DOXYGEN) 
else
	@echo "Doxygen not detected, skipping documentation build."
endif

clean-local:
	-rm -rf html/
	-rm Makefile
	-rm Makefile.in


.PHONY: html-local clean-local

BUILT_SOURCES = cap_names.h
lib_LTLIBRARIES = libcreds-3.0.la
bin_PROGRAMS = creds-get creds-test

library_includedir=$(includedir)/libcreds-3.0
library_include_HEADERS=sys/creds.h

libcreds_3_0_la_LDFLAGS = -version-info 1:0:0
libcreds_3_0_la_SOURCES = creds.c credsctl.c cap_names.h
libcreds_3_0_la_LIBADD = @LIBSMACKMAN_1_0_LIBS@ @LIBSMACK_1_0_LIBS@
libcreds_3_0_la_CFLAGS = @LIBSMACKMAN_1_0_CFLAGS@ @LIBSMACK_1_0_CFLAGS@

creds_test_SOURCES = creds-test.c
creds_test_LDADD = $(top_builddir)/.libs/libcreds-3.0.la

creds_get_SOURCES = creds-get.c
creds_get_LDADD = $(top_builddir)/.libs/libcreds-3.0.la

cap_names.h : Makefile /usr/include/linux/capability.h
	perl capnames.pl < /usr/include/linux/capability.h > cap_names.h

distclean-local:
	-rm cap_names.h
	-rm aclocal.m4
	-rm Makefile
	-rm Makefile.in
	-rm configure
	-rm -rf autom4te.cache
	-rm -rf m4
	-rm config.*
	-rm ltmain.sh
	-rm libtool
	-rm depcomp
	-rm install-sh
	-rm missing
	-rm INSTALL

SUBDIRS = dox

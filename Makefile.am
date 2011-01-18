BUILT_SOURCES = cap_names.h
lib_LTLIBRARIES = libcreds.la
bin_PROGRAMS = creds-get creds-test

nobase_include_HEADERS = sys/creds.h

libcreds_la_LDFLAGS = -version-info 3:0
libcreds_la_SOURCES = creds.c credsctl.c cap_names.h
libcreds_la_LIBADD = -lsmack

creds_test_SOURCES = creds-test.c
creds_test_LDADD = -L.libs -lcreds

creds_get_SOURCES = creds-get.c
creds_get_LDADD = -L.libs -lcreds


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

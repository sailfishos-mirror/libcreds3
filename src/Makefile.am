BUILT_SOURCES = cap_names.h
lib_LTLIBRARIES = libcreds.la

libcreds_la_LDFLAGS = -version-info 3:0:0
libcreds_la_SOURCES = creds.c credsctl.c cap_names.h
libcreds_la_LIBADD = @LIBSMACKMAN_LIBS@ @LIBSMACK_LIBS@ -lcap
libcreds_la_CFLAGS = @LIBSMACKMAN_CFLAGS@ @LIBSMACK_CFLAGS@

cap_names.h : Makefile /usr/include/linux/capability.h
	perl capnames.pl < /usr/include/linux/capability.h > cap_names.h

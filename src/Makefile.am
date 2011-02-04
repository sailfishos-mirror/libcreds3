BUILT_SOURCES = cap_names.h
lib_LTLIBRARIES = libcreds3.la

libcreds3_la_LDFLAGS = -version-info 1:0:0
libcreds3_la_SOURCES = creds.c credsctl.c cap_names.h
libcreds3_la_LIBADD = @LIBSMACKMAN_LIBS@ @LIBSMACK_LIBS@
libcreds3_la_CFLAGS = @LIBSMACKMAN_CFLAGS@ @LIBSMACK_CFLAGS@

cap_names.h : Makefile /usr/include/linux/capability.h
	perl capnames.pl < /usr/include/linux/capability.h > cap_names.h

AM_CPPFLAGS = -I../src

TESTS = check_creds

bin_PROGRAMS = check_creds

check_creds_SOURCES = check_creds.c
check_creds_CFLAGS = @CHECK_CFLAGS@ @LIBSMACKMAN_1_0_CFLAGS@
check_creds_LDADD = -L$(top_builddir)/src/.libs -lcreds @CHECK_LIBS@ @LIBSMACKMAN_1_0_LIBS@

newns_SOURCES = newns.c

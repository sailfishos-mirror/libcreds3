AC_PREREQ(2.59)
AC_INIT([libcreds3],[1.0])
AM_INIT_AUTOMAKE(gnu 0.0.1 no-define dist-bzip2)
AC_PROG_CC
AC_PROG_CXX
AC_PROG_INSTALL
AC_PROG_LIBTOOL

# Checks for programs
AC_CHECK_PROG([DOXYGEN], [doxygen], [doxygen], [])
AC_MSG_CHECKING([wheter to add documentation targets])
if test ! -z "$DOXYGEN"; then
	AC_MSG_RESULT([yes])
else
	AC_MSG_RESULT([no])
fi
# and create a condition for the dox/Makefile.am
AM_CONDITIONAL([DOXY_DOC],[test ! -z "$DOXYGEN"])

# This second $DOXYGEN variable is used inside dox/Makefile.am
AC_SUBST([DOXYGEN], [$DOXYGEN])

AC_CONFIG_MACRO_DIR([m4])
AC_PROG_MAKE_SET
AC_CHECK_HEADERS(linux/aegis/creds.h)
AC_CHECK_HEADERS(sys/smack.h)
AC_OUTPUT(Makefile dox/Makefile)

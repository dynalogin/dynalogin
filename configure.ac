

AC_INIT(dynalogin,0.9.14)
AC_CONFIG_SRCDIR(libdynalogin/dynalogin.c)

AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE

AC_CANONICAL_HOST
AM_CONFIG_HEADER(config.h)

AC_LIBTOOL_WIN32_DLL

AC_PROG_CC
gl_EARLY
gl_INIT

AC_PROG_INSTALL

AC_PROG_LIBTOOL

PKG_CHECK_MODULES([DEPS_LIBDYNALOGIN], [liboath >= 1.10.2 apr-1 >= 1.4.2])
PKG_CHECK_MODULES([DEPS_DYNALOGIND], [apr-1 >= 1.4.2 gnutls >= 2.12])
PKG_CHECK_MODULES([DEPS_LIBDYNALOGINCLIENT], [gnutls >= 2.8])

AC_CHECK_HEADERS([security/pam_appl.h], [],
  [AC_MSG_ERROR([[PAM header files not found, install libpam-dev.]])])
AC_CHECK_HEADERS([security/pam_modules.h security/_pam_macros.h], [], [],
  [#include <security/pam_appl.h>])

AC_CHECK_LIB(pam, pam_get_item)

AC_OUTPUT(
	Makefile
	libdynalogin/Makefile
	libdynalogin/datasources/Makefile
	libdynalogin/datasources/example/Makefile
	libdynalogin/datasources/fs/Makefile
	libdynalogin/datasources/odbc/Makefile
	libdynalogin/lib/Makefile
	dynalogind/Makefile
	libdynaloginclient/Makefile
	pam_dynalogin/Makefile
	)


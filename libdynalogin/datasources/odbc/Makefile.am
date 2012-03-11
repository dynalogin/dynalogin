
EXTRA_DIST = odbc.ini-sample odbcinst.ini-sample README.mysql schema_mysql.sql

AM_CFLAGS = -I../../ -DLOCALSTATEDIR='"$(localstatedir)"' $(DEPS_LIBDYNALOGIN_CFLAGS)

pkglib_LTLIBRARIES = odbc_ds.la
odbc_ds_la_SOURCES = odbc_ds.c
odbc_ds_la_LIBADD = $(DEPS_LIBDYNALOGIN_LIBS)
odbc_ds_la_LDFLAGS = -module -avoid-version -lodbc


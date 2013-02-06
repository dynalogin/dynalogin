AUTOMAKE_OPTIONS = foreign dist-tarZ
ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = libhotp.map

SUBDIRS = lib datasources

LIB_RELEASE = 1
VERSION_INFO = 1:0:0

AM_CFLAGS = -DSYSCONFDIR='"$(sysconfdir)"' -DPKGLIBDIR='"$(pkglibdir)"' $(DEPS_LIBDYNALOGIN_CFLAGS)
AM_CFLAGS += -I$(srcdir)/lib -I$(builddir)/lib

lib_LTLIBRARIES = libdynalogin.la
libdynalogin_la_SOURCES = dynalogin.c hotpdigest.c dynalogin.h dynalogin-types.h dynalogin-datastore.h hotpdigest.h dynalogin-internal.h
libdynalogin_la_LIBADD = lib/libgnu.la $(DEPS_LIBDYNALOGIN_LIBS)
libdynalogin_la_LDFLAGS = -version-info $(VERSION_INFO) -release $(LIB_RELEASE) -export-dynamic


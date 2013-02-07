AUTOMAKE_OPTIONS = foreign dist-tarZ
ACLOCAL_AMFLAGS = -I m4

SUBDIRS = datasources

LIB_RELEASE = 1
VERSION_INFO = 1:0:0

lib_LTLIBRARIES = libdynalogin.la
libdynalogin_la_SOURCES = dynalogin.c hotpdigest.c dynalogin.h dynalogin-types.h dynalogin-datastore.h hotpdigest.h dynalogin-internal.h
libdynalogin_la_CFLAGS = -DSYSCONFDIR='"$(sysconfdir)"'
libdynalogin_la_CFLAGS += -DPKGLIBDIR='"$(pkglibdir)"'
libdynalogin_la_CFLAGS += $(DEPS_LIBDYNALOGIN_CFLAGS)
libdynalogin_la_LIBADD = $(DEPS_LIBDYNALOGIN_LIBS)
libdynalogin_la_LDFLAGS = -version-info $(VERSION_INFO) -release $(LIB_RELEASE) -export-dynamic


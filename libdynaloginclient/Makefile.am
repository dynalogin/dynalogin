AUTOMAKE_OPTIONS = foreign dist-tarZ
ACLOCAL_AMFLAGS = -I m4

#AM_CFLAGS = -DSYSCONFDIR='"$(sysconfdir)"' -DPKGLIBDIR='"$(pkglibdir)"' $(DEPS_LIBDYNALOGIN_CFLAGS)
#AM_CFLAGS += -I$(srcdir)/lib -I$(builddir)/lib

lib_LTLIBRARIES = libdynaloginclient.la
libdynaloginclient_la_SOURCES = dynaloginclient.c dynaloginclient.h
libdynaloginclient_la_CPPFLAGS = $(DEPS_LIBDYNALOGINCLIENT_CPPFLAGS)
libdynaloginclient_la_LIBADD = $(DEPS_LIBDYNALOGINCLIENT_LIBS)
libdynaloginclient_la_LDFLAGS = -version-info 0:0:0 -release 1 -export-dynamic

TESTS = test_client

check_PROGRAMS = test_client

test_client_SOURCES = test_client.c
test_client_LDADD = libdynaloginclient.la


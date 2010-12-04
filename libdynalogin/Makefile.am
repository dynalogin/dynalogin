AUTOMAKE_OPTIONS = foreign dist-tarZ
ACLOCAL_AMFLAGS = -I m4

#EXTRA_DIST =

SUBDIRS = lib datasources

AM_CFLAGS = -DSYSCONFDIR='"$(sysconfdir)"' -DPKGLIBDIR='"$(pkglibdir)"'
AM_CFLAGS += -I$(srcdir)/lib -I$(builddir)/lib

AM_LDFLAGS = -lapr-1

lib_LTLIBRARIES = libdynalogin.la
libdynalogin_la_SOURCES = dynalogin.c hotp.c
libdynalogin_la_LIBADD = lib/libgnu.la
libdynalogin_la_LDFLAGS = -version-info 0:0:0 -release 1 -export-dynamic


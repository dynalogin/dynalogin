AUTOMAKE_OPTIONS = foreign dist-tarZ
ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = doc m4/gnulib-tool.m4 m4/gnulib-cache.m4 phpMyID-dynalogin
dist-hook:
	rm -rf `find $(distdir)/doc -name .svn`
	rm -rf `find $(distdir)/phpMyID-dynalogin -name .svn`

SUBDIRS = libdynalogin dynalogind

AM_CFLAGS = -DSYSCONFDIR='"$(sysconfdir)"' -DPKGLIBDIR='"$(pkglibdir)"'
AM_CFLAGS += -I$(srcdir)/libdynalogin 
#-I$(builddir)/lib +=

AM_LDFLAGS = -lapr-1

bin_PROGRAMS = dynalogin_tester
dynalogin_tester_SOURCES = dynalogin_tester.c
dynalogin_tester_LDADD = libdynalogin/libdynalogin.la -lapr-1 -loath




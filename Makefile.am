AUTOMAKE_OPTIONS = foreign dist-tarZ
ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = doc \
	digest.sh \
	m4/gnulib-tool.m4 m4/gnulib-cache.m4 \
	php \
	simpleid
dist-hook:
	rm -rf `find $(distdir)/doc -name .svn`

SUBDIRS = libdynalogin dynalogind

bin_PROGRAMS = dynalogin_tester
dynalogin_tester_SOURCES = dynalogin_tester.c
dynalogin_tester_CFLAGS = -DSYSCONFDIR='"$(sysconfdir)"' -DPKGLIBDIR='"$(pkglibdir)"'
dynalogin_tester_CFLAGS += -I$(srcdir)/libdynalogin
dynalogin_tester_CFLAGS += $(DEPS_DYNALOGIND_CFLAGS)
dynalogin_tester_LDADD = libdynalogin/libdynalogin.la
dynalogin_tester_LDADD += $(DEPS_DYNALOGIND_LIBS)


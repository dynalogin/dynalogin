

AUTOMAKE_OPTIONS = foreign dist-tarZ
ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = dynalogind.conf

SUBDIRS = 

sbin_PROGRAMS = dynalogind
dynalogind_SOURCES = dynalogind.c
dynalogind_CFLAGS = -DSYSCONFDIR='"$(sysconfdir)"' -DPKGLIBDIR='"$(pkglibdir)"'
dynalogind_CFLAGS += -I../libdynalogin
dynalogind_CFLAGS += $(DEPS_DYNALOGIND_CFLAGS)
dynalogind_LDADD = ../libdynalogin/libdynalogin.la
dynalogind_LDADD += $(DEPS_DYNALOGIND_LIBS)

man_MANS = dynalogind.1
EXTRA_DIST += $(man_MANS)


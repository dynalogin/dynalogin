

AUTOMAKE_OPTIONS = foreign dist-tarZ
ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = dynalogind.conf

SUBDIRS = 

AM_CFLAGS = -DSYSCONFDIR='"$(sysconfdir)"' -DPKGLIBDIR='"$(pkglibdir)"'
AM_CFLAGS += -I../libdynalogin 
#-I$(builddir)/lib +=

AM_LDFLAGS = -lapr-1

sbin_PROGRAMS = dynalogind
dynalogind_SOURCES = dynalogind.c
dynalogind_LDADD = ../libdynalogin/libdynalogin.la -lapr-1

man1_MANS = dynalogind.1


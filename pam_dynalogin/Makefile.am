AUTOMAKE_OPTIONS = foreign dist-tarZ
ACLOCAL_AMFLAGS = -I m4


pammoddir = $(exec_prefix)/lib/security
pammod_LTLIBRARIES = pam_dynalogin.la

pam_dynalogin_la_SOURCES = pam_dynalogin.c
pam_dynalogin_la_CPPFLAGS = -DSYSCONFDIR='"$(sysconfdir)"'
pam_dynalogin_la_CPPFLAGS += -I$(builddir)/../libdynaloginclient
pam_dynalogin_la_CPPFLAGS += $(DEPS_LIBDYNALOGINCLIENT_CPPFLAGS)
pam_dynalogin_la_LIBADD = ../libdynaloginclient/libdynaloginclient.la
pam_dynalogin_la_LIBADD += $(DEPS_LIBDYNALOGINCLIENT_LIBS) -lpam
pam_dynalogin_la_LDFLAGS = -module -avoid-version


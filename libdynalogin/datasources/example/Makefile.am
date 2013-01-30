

AM_CFLAGS = -I../../
AM_CFLAGS += $(DEPS_LIBDYNALOGIN_CFLAGS)

pkglib_LTLIBRARIES = example_ds.la
example_ds_la_SOURCES = example_ds.c
example_ds_la_LIBADD = $(DEPS_LIBDYNALOGIN_LIBS)
example_ds_la_LDFLAGS = -module -avoid-version

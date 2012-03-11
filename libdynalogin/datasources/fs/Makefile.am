

AM_CFLAGS = -I../../ -DLOCALSTATEDIR='"$(localstatedir)"' $(DEPS_LIBDYNALOGIN_CFLAGS)

pkglib_LTLIBRARIES = fs_ds.la
fs_ds_la_SOURCES = fs_ds.c
fs_ds_la_LIBADD = $(DEPS_LIBDYNALOGIN_LIBS)
fs_ds_la_LDFLAGS = -module -avoid-version

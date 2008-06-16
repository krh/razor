## Process this file with automake to produce Makefile.in

INCLUDES = \
	-I$(top_builddir)/src -I$(top_srcdir)/src \
	-DPACKAGE_LIBEXEC_DIR=\""$(libexecdir)"\" \
	-DPACKAGE_SYSCONF_DIR=\""$(sysconfdir)"\" \
	-DPACKAGE_DATA_DIR=\""$(datadir)"\" \
	-DPACKAGE_BIN_DIR=\""$(bindir)"\" \
	-DPACKAGE_LOCALSTATE_DIR=\""$(localstatedir)"\" \
	-DPACKAGE_LOCALE_DIR=\""$(localedir)"\" \
	-DPACKAGE_LIB_DIR=\""$(libdir)"\"

lib_LTLIBRARIES = librazor.la

librazorincludedir = $(includedir)/razor

librazorinclude_HEADERS =              			\
	razor.h

librazor_la_SOURCES =                                	\
	razor-internal.h				\
	razor.h						\
	razor.c						\
	razor-root.c					\
	types.h						\
	types.c						\
	util.c						\
	rpm.c

librazor_la_LIBADD = $(ZLIB_LIBS)

clean-local :
	rm -f *~


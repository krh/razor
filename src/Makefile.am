## Process this file with automake to produce Makefile.in

INCLUDES = \
	$(CURL_CFLAGS) \
	$(EXPAT_CFLAGS) \
	$(RPM_CFLAGS) \
	-I$(top_builddir)/src -I$(top_srcdir)/src \
	-I$(top_srcdir)/librazor \
	-DPACKAGE_LIBEXEC_DIR=\""$(libexecdir)"\" \
	-DPACKAGE_SYSCONF_DIR=\""$(sysconfdir)"\" \
	-DPACKAGE_DATA_DIR=\""$(datadir)"\" \
	-DPACKAGE_BIN_DIR=\""$(bindir)"\" \
	-DPACKAGE_LOCALSTATEDIR=\""$(localstatedir)"\" \
	-DPACKAGE_LOCALE_DIR=\""$(localedir)"\"

bin_PROGRAMS = razor
noinst_PROGRAMS = rpm
check_PROGRAMS = test-driver

razor_SOURCES = main.c import-rpmdb.c import-yum.c
razor_LDADD = $(RPM_LIBS) $(EXPAT_LIBS) $(CURL_LIBS) $(top_builddir)/librazor/librazor.la

rpm_SOURCES = rpm.c
rpm_LDADD = $(top_builddir)/librazor/librazor.la

test_driver_SOURCES = test-driver.c
test_driver_LDADD = $(EXPAT_LIBS) $(top_builddir)/librazor/librazor.la

TESTS = test-driver

clean-local :
	rm -f *~


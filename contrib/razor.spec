Summary:   Razor is a package management system replacing rpm and yum
Name:      razor
Version:   0.1
Release:   0.1%{?dist}
License:   GPLv2+
Group:     System Environment/Libraries
URL:       http://github.com/krh/razor/wikis
Source0:   http://people.freedesktop.org/~krh/releases/%{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

Requires: expat
Requires: rpm-libs

BuildRequires: expat-devel
BuildRequires: libtool
BuildRequires: gettext
BuildRequires: libcurl-devel
BuildRequires: rpm-devel
BuildRequires: zlib-devel
BuildRequires: perl(XML::Parser)

%description
Razor is a package management system replacing rpm and yum.
Razor implements management of packages installed on the system,
dependency solving, and upgrading in a small compact code base with
minimal dependencies.

%package libs
Summary: Libraries for accessing razor
Group: Development/Libraries
Requires: expat >= %{dbus_version}
Requires: %{name} = %{version}-%{release}

%description libs
Libraries for accessing razor.

%package devel
Summary: Libraries and headers for razor
Group: Development/Libraries
Requires: %{name} = %{version}-%{release}
Requires: pkgconfig
Requires: libcurl-devel
Requires: rpm-devel
Requires: zlib-devel

%description devel
Headers and libraries for razor.

%prep
%setup -q

%build
%configure

make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT

rm -f $RPM_BUILD_ROOT%{_libdir}/librazor*.a
rm -f $RPM_BUILD_ROOT%{_libdir}/librazor*.la
mv $RPM_BUILD_ROOT%{_bindir}/rpm $RPM_BUILD_ROOT%{_bindir}/rpm-razor

#%find_lang %name

%clean
rm -rf $RPM_BUILD_ROOT

%post libs -p /sbin/ldconfig

%postun libs -p /sbin/ldconfig

%files
# -f %{name}.lang
%defattr(-,root,root,-)
%doc README AUTHORS NEWS COPYING
%dir %{_datadir}/doc/razor
%doc %{_datadir}/doc/razor/*.txt
%config %{_sysconfdir}/bash_completion.d/*.sh
%{_bindir}/razor
%{_bindir}/rpm-razor
%exclude %{_libdir}/librazor*.so.*

%files libs
%defattr(-,root,root,-)
%doc README AUTHORS NEWS COPYING
%{_libdir}/*razor*.so.*

%files devel
%defattr(-,root,root,-)

%{_libdir}/lib*.so
%{_libdir}/pkgconfig/*
%{_includedir}/*

%changelog
* Mon Jun 16 2008 Richard Hughes <richard@hughsie.com> 0.1-0.1
- Initial version


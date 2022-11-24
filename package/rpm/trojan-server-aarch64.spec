Name:           trojan-server
Version:        0.0.1
Release:        1%{?dist}
Summary:        TrojanX Server for SSPanel-UIM.
Group:          Unspecified
License:        MPL-2.0
URL:            https://github.com/sspanel-uim/TrojanX
Packager:       SSPanel-UIM Team <package@sspanel.org>
BuildRequires:  systemd

%description
A Trojan implementation from SSPanel-UIM.

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_sysconfdir}/trojan-server
mkdir -p %{buildroot}%{_sysconfdir}/systemd/system
install -m 755 %{_builddir}/%{name}-%{version}/trojan-sspanel-x86_64-unknown-linux-gnu %{buildroot}%{_bindir}/trojan-server
install -m 644 %{_builddir}/%{name}-%{version}/sspanel.json %{buildroot}%{_sysconfdir}/trojan-server
install -m 644 %{_builddir}/%{name}-%{version}/trojan-server.service %{buildroot}%{_sysconfdir}/systemd/system

%post

%postun

%clean
rm -rf %{buildroot}

%files
%attr(0755, root, root) %{_bindir}/trojan-server
%attr(0755, root, root) %{_sysconfdir}/trojan-server
%attr(0644, root, root) %{_sysconfdir}/trojan-server/sspanel.json
%attr(0644, root, root) %{_sysconfdir}/systemd/system/trojan-server.service

%changelog
* Sun Jul 24 2022 SSPanel-UIM Team <package@sspanel.org> - 0.0.1-1
 - First release of TrojanX.

* Sun Aug 30 2022 SSPanel-UIM Team <package@sspanel.org> - 0.0.2-1
 - Bugfixes & Performance improvement.

* Sun Nov 24 2022 SSPanel-UIM Team <package@sspanel.org> - 0.0.3-1
 - Bugfixes & Performance improvement.

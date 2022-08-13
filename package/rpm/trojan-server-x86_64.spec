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
mkdir -p %{buildroot}%{_unitdir}
install -m 755 %{_builddir}/%{name}-%{version}/trojan-sspanel-x86_64-unknown-linux-gnu %{buildroot}%{_bindir}/trojan-server
install -m 644 %{_builddir}/%{name}-%{version}/sspanel.json %{buildroot}%{_sysconfdir}/trojan-server
install -m 644 %{_builddir}/%{name}-%{version}/trojan-server.service %{buildroot}%{_unitdir}

%post
/usr/sbin/groupadd trojan
/usr/sbin/useradd -g trojan trojan

%postun
/usr/sbin/userdel -r trojan
/usr/sbin/groupdel trojan

%clean
rm -rf %{buildroot}

%files
%{_bindir}/trojan-server
%{_sysconfdir}/trojan-server/sspanel.json
%{_unitdir}/trojan-server.service

%changelog
* Sun Jul 24 2022 SSPanel-UIM Team <package@sspanel.org> - 0.0.1-1
 - First release of TrojanX.
# flexisip-http-file-transfer-server, as kelixip runs it: upstream's code at a
# pinned commit, the PDO patch (a PostgreSQL subscriber base), and the
# configuration of an AL9 host with php-fpm. Upstream's own spec builds from a
# `git describe` and installs an Apache config that only mod_php reads; this one
# builds from a tarball of the commit and ships its own (packaging/fhft/README.md).
#
# The name is upstream's: this is their package, slightly modified. Version and
# the head of Release are what upstream's Makefile derives from the commit's tag
# (1.1.1-alpha, 0 commits after it); `.pdoN` counts our builds of it and goes
# back to 1 when the commit changes (CLAUDE.md, "Changing the version").

%global commit   524ab71
%global var_dir  /var/opt/belledonne-communications
%global opt_dir  /opt/belledonne-communications/share/flexisip-http-file-transfer-server
%global tmp_dir  %{var_dir}/flexisip-http-file-transfer-tmp
%global conf_dir %{_sysconfdir}/flexisip-http-file-transfer-server

Name:           bc-flexisip-http-file-transfer-server
Version:        1.1.1
Release:        0.alpha.0+%{commit}.pdo1%{?dist}
Summary:        Flexisip HTTP File Transfer server (PDO, php-fpm)

License:        AGPL-3.0-or-later
URL:            https://github.com/BelledonneCommunications/flexisip-http-file-transfer-server
# git archive --prefix=flexisip-http-file-transfer-server-%%{commit}/ %%{commit}
Source0:        flexisip-http-file-transfer-server-%{commit}.tar.gz
# The site configuration: digest on, realm from the From, PDO, logging off.
Source1:        flexisip-http-file-transfer-server.conf
Source2:        fhft.inc
Source3:        zz-fhft-vhost.conf
Source4:        user.ini
# PDO instead of mysqli: MySQL as before, or PostgreSQL through AUTH_DB_DSN.
Patch0:         common-pdo.patch

BuildArch:      noarch

Requires:       httpd
Requires:       mod_ssl
Requires:       php-fpm
Requires:       php-pdo
Requires:       php-xml
Requires:       cronie
Requires:       logrotate
# The driver of the subscriber base: PostgreSQL for kelixip, MySQL for Flexisip's.
Recommends:     php-pgsql
Suggests:       php-mysqlnd
Requires(post): policycoreutils-python-utils
Requires(postun): policycoreutils-python-utils

%description
A PHP script implementing RCS RCC.07 v6.0 section 3.5.4.8, File Transfer via
HTTP: the store Linphone uploads chat attachments to. This build reads the
subscriber base through PDO, so it may be PostgreSQL, runs under php-fpm, and
serves the uploaded files statically under /files/tmp/ of its own virtual host.

%prep
%autosetup -n flexisip-http-file-transfer-server-%{commit} -p1

%build
# PHP: nothing to build.

%install
install -d %{buildroot}%{opt_dir}
install -m 0644 src/*.php %{buildroot}%{opt_dir}/
# php-fpm reads the upload limits here; upstream's php_value lines need mod_php
install -m 0644 %{SOURCE4} %{buildroot}%{opt_dir}/.user.ini

install -d -m 0750 %{buildroot}%{tmp_dir}
install -d %{buildroot}%{var_dir}/log
touch %{buildroot}%{var_dir}/log/flexisip-http-file-transfer-server.log

install -d %{buildroot}%{conf_dir}
install -m 0640 %{SOURCE1} %{buildroot}%{conf_dir}/flexisip-http-file-transfer-server.conf

# fhft.inc is loaded by the vhost alone (its name does not end in .conf); the
# vhost names a certificate, so it ships as a sample to copy and complete
install -d %{buildroot}%{_sysconfdir}/httpd/conf.d
install -m 0644 %{SOURCE2} %{buildroot}%{_sysconfdir}/httpd/conf.d/fhft.inc
install -m 0644 %{SOURCE3} %{buildroot}%{_sysconfdir}/httpd/conf.d/zz-fhft-vhost.conf.sample

install -d %{buildroot}%{_sysconfdir}/cron.d
install -m 0644 cron.d/flexisip-http-file-transfer-server %{buildroot}%{_sysconfdir}/cron.d/
install -d %{buildroot}%{_sysconfdir}/logrotate.d
install -m 0644 logrotate/flexisip-http-file-transfer-server.conf %{buildroot}%{_sysconfdir}/logrotate.d/

%post
# cron reads fresh files only: touch it once installed (upstream does the same)
touch %{_sysconfdir}/cron.d/flexisip-http-file-transfer-server
if selinuxenabled 2>/dev/null; then
  setsebool -P httpd_can_network_connect_db on || :
  semanage fcontext -a -t httpd_sys_rw_content_t '%{var_dir}(/.*)?' 2>/dev/null || :
  restorecon -R %{var_dir} || :
fi

%postun
if [ "$1" -eq 0 ] && selinuxenabled 2>/dev/null; then
  semanage fcontext -d '%{var_dir}(/.*)?' 2>/dev/null || :
fi

%files
%license LICENSE.txt
%doc README.md
%dir /opt/belledonne-communications
%dir /opt/belledonne-communications/share
%dir %{opt_dir}
%{opt_dir}/*.php
%config(noreplace) %{opt_dir}/.user.ini
%dir %{var_dir}
%dir %attr(0750,apache,apache) %{tmp_dir}
%dir %attr(0755,apache,apache) %{var_dir}/log
%ghost %attr(0644,apache,apache) %{var_dir}/log/flexisip-http-file-transfer-server.log
%dir %{conf_dir}
%config(noreplace) %attr(0640,root,apache) %{conf_dir}/flexisip-http-file-transfer-server.conf
%config(noreplace) %{_sysconfdir}/httpd/conf.d/fhft.inc
%{_sysconfdir}/httpd/conf.d/zz-fhft-vhost.conf.sample
%config(noreplace) %{_sysconfdir}/cron.d/flexisip-http-file-transfer-server
%config(noreplace) %{_sysconfdir}/logrotate.d/flexisip-http-file-transfer-server.conf

%changelog
* Wed Oct 07 2026 Emmanuel BUU <latribuu@proton.me> - 1.1.1-0.alpha.0+524ab71.pdo1
- Upstream 524ab71 (1.1.1-alpha), built from a tarball of the commit.
- common-pdo.patch: the subscriber base through PDO; AUTH_DB_DSN names it,
  MySQL from AUTH_DB_HOST/AUTH_DB_NAME without it.
- php-fpm: the upload limits in .user.ini; upstream's Apache config, which only
  mod_php reads, replaced by fhft.inc and a vhost sample; downloads static.

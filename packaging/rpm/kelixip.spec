# kelixip.spec — Alma Linux 9 (design docs/kelixip_basic_design.md §12.1, §15 P10).
#
# The payload is PRE-BUILT: Source0 is the staged tarball produced by
# packaging/stage.sh (an assembled `mix release` tree with embedded ERTS, plus the
# module .beam files). Read packaging/README.md before building — the release must
# be assembled on Alma Linux 9, because the embedded ERTS links this host's
# glibc/OpenSSL/ncurses.
#
#   rpmbuild -bb --define "_topdir <dir>" packaging/rpm/kelixip.spec

# The payload is already stripped as much as it may be: brp-strip on beam.smp and
# on the NIF .so buys nothing and risks a broken runtime. Same for debuginfo.
%global debug_package %{nil}
%global __os_install_post %{nil}
# No debuginfo ships, so /usr/lib/.build-id links would point at binaries nobody
# can symbolise — clutter, and a file-conflict surface if another package ever
# ships the same ERTS.
%global _build_id_links none

# The release is arch-dependent (embedded ERTS) but lives in an arch-independent
# path, as the FHS layout of the design doc specifies.
%global kelixdir %{_prefix}/lib/kelixip

# Requires ARE wanted — they pin the AL9 libcrypto/libtinfo/glibc the embedded ERTS
# is linked against. Provides are not: the crypto NIF .so must not advertise itself
# as a system library.
%global __provides_exclude_from ^%{kelixdir}/.*$

Name:           kelixip
Version:        0.2.0
Release:        1%{?dist}
Summary:        kelixip SIP application server
License:        Proprietary
URL:            https://www.ives.fr/
Source0:        %{name}-%{version}.tar.gz
ExclusiveArch:  x86_64 aarch64

BuildRequires:  systemd-rpm-macros
Requires(pre):  shadow-utils
%{?systemd_requires}

%description
kelixip is a SIP application server: declarative per-domain dispatch (config.toml
+ domains.toml) onto scenario scripts, a REST/CLI control surface (kelictl), and
Prometheus metrics.

The core ships NO SIP function. The registrar and the authentication back-end are
loadable modules delivered as separate packages (kelixip-mod-registrar,
kelixip-mod-auth_db) which drop their bytecode into the root-owned module
directory; a deployment installs only what it uses.

This package embeds its own Erlang runtime — no system Erlang or Elixir is needed.

%package mod-registrar
Summary:        Registrar / user-location module for kelixip
Requires:       %{name} = %{version}-%{release}

%description mod-registrar
The usrloc store: per-domain contact bindings with NAT/flow handling (received,
flow, Path), expiry bounds and the save/lookup/subscribe facade the registrar
scripts drive. Enable it with a [module.registrar] block in domains.toml.

%package mod-auth_db
Summary:        Database authentication module for kelixip
Requires:       %{name} = %{version}-%{release}

%description mod-auth_db
Digest authentication against a MariaDB/MySQL subscriber table (kamailio-compatible
ha1/ha1b columns): it owns the challenge/accept/reject decision, the scripts only
compose the SIP response. Enable it with a [module.auth_db] block in config.toml.

%prep
%setup -q

%build
# Nothing to build: Source0 carries the assembled release (see packaging/README.md).

%install
rm -rf %{buildroot}

# The release itself, plus the root-owned directory modules are loaded from.
install -d -m 0755 %{buildroot}%{kelixdir}
cp -a rel/. %{buildroot}%{kelixdir}/
install -d -m 0755 %{buildroot}%{kelixdir}/modules

# The loadable modules (each goes to its own subpackage below).
install -m 0644 modules/*.beam %{buildroot}%{kelixdir}/modules/

# kelictl is a command inside the release; kelixip is the release's own control
# script. Both resolve their own symlink, so /usr/sbin entries are enough.
install -d -m 0755 %{buildroot}%{_sbindir}
ln -s ../lib/kelixip/bin/kelictl %{buildroot}%{_sbindir}/kelictl
ln -s ../lib/kelixip/bin/kelixip %{buildroot}%{_sbindir}/kelixip

# script_dir — the reference scenario scripts.
install -d -m 0755 %{buildroot}%{_datadir}/%{name}
install -m 0644 scripts/*.exs %{buildroot}%{_datadir}/%{name}/

# Configuration. 0640 root:kelixip: config.toml holds the DB password and the API
# token, so the service reads it and nobody else does.
install -d -m 0750 %{buildroot}%{_sysconfdir}/%{name}
install -d -m 0750 %{buildroot}%{_sysconfdir}/%{name}/tls
install -m 0640 config/config.toml  %{buildroot}%{_sysconfdir}/%{name}/config.toml
install -m 0640 config/domains.toml %{buildroot}%{_sysconfdir}/%{name}/domains.toml
install -d -m 0755 %{buildroot}%{_sysconfdir}/sysconfig
install -m 0644 sysconfig/kelixip %{buildroot}%{_sysconfdir}/sysconfig/%{name}

install -D -m 0644 systemd/kelixip.service %{buildroot}%{_unitdir}/%{name}.service

# Mutable state (future usrloc persistence, operator-installed scripts) and the log
# directory used when stdout is redirected. The unit also declares them, so a
# tmpfs-only deployment still gets them.
install -d -m 0750 %{buildroot}%{_sharedstatedir}/%{name}
install -d -m 0750 %{buildroot}%{_localstatedir}/log/%{name}

# The distribution cookie is NOT shipped: one cookie baked into the package would
# be the same secret on every installation. %post generates one per host.
rm -f %{buildroot}%{kelixdir}/releases/COOKIE

%pre
getent group kelixip >/dev/null || groupadd -r kelixip
getent passwd kelixip >/dev/null || \
    useradd -r -g kelixip -d %{_sharedstatedir}/%{name} -s /sbin/nologin \
            -c "kelixip SIP server" kelixip
exit 0

%post
# Per-host distribution cookie: the credential kelictl authenticates with. Kept
# across upgrades; readable by the service and by root only.
if [ ! -s %{kelixdir}/releases/COOKIE ]; then
    ( umask 077
      head -c 32 /dev/urandom | base64 > %{kelixdir}/releases/COOKIE )
    chown root:kelixip %{kelixdir}/releases/COOKIE
    chmod 0640 %{kelixdir}/releases/COOKIE
fi
%systemd_post %{name}.service

%preun
%systemd_preun %{name}.service

%postun
%systemd_postun_with_restart %{name}.service
if [ $1 -eq 0 ]; then
    rm -f %{kelixdir}/releases/COOKIE
fi

%files
%doc doc/*.md
%dir %attr(0750,root,kelixip) %{_sysconfdir}/%{name}
%dir %attr(0750,root,kelixip) %{_sysconfdir}/%{name}/tls
%config(noreplace) %attr(0640,root,kelixip) %{_sysconfdir}/%{name}/config.toml
%config(noreplace) %attr(0640,root,kelixip) %{_sysconfdir}/%{name}/domains.toml
%config(noreplace) %attr(0644,root,root) %{_sysconfdir}/sysconfig/%{name}
%{_unitdir}/%{name}.service
%{_sbindir}/kelictl
%{_sbindir}/kelixip
%{_datadir}/%{name}
%dir %attr(0755,root,root) %{kelixdir}
%{kelixdir}/bin
%{kelixdir}/erts-*
%{kelixdir}/lib
%{kelixdir}/releases
# Root-owned and not writable by the service: loading a .beam is executing code.
%dir %attr(0755,root,root) %{kelixdir}/modules
%ghost %attr(0640,root,kelixip) %{kelixdir}/releases/COOKIE
%dir %attr(0750,kelixip,kelixip) %{_sharedstatedir}/%{name}
%dir %attr(0750,kelixip,kelixip) %{_localstatedir}/log/%{name}

%files mod-registrar
%{kelixdir}/modules/Elixir.Kelix.Mod.Registrar*.beam

%files mod-auth_db
%{kelixdir}/modules/Elixir.Kelix.Mod.AuthDb*.beam

%changelog
* Tue Jul 28 2026 Emmanuel BUU <emmanuel.buu@ives.fr> - 0.2.0-1
- First packaged release (design P10): core + mod-registrar + mod-auth_db
  subpackages, systemd unit with graceful-shutdown ExecStop, per-host cookie.

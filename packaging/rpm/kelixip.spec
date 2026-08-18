# kelixip.spec — Alma Linux 9 (design docs/design/kelixip_basic_design.md §12.1, §15 P10).
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
Version:        1.5.0
Release:        1%{?dist}
Summary:        kelixip SIP application server
License:        BSL-1.1
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

The core ships NO SIP function. The registrar, the authentication back-end and the
conference mixer are loadable modules delivered as separate packages
(kelixip-mod-registrar, kelixip-mod-auth_db, kelixip-mod-mcu) which drop their
bytecode into the root-owned module directory; a deployment installs only what it
uses.

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

%package mod-mcu
Summary:        Conference mixer (MCU) module for kelixip
Requires:       %{name} = %{version}-%{release}

%description mod-mcu
Audio/video/text conferencing: conferences addressed by DID, a mixed audio leg and
a video mosaic per participant, driven over the Medooze MCU XML-RPC API, with the
REST/CLI surface (conference.*, participant.*, recording.*, slot.*) to inspect and
steer a live mix. Enable it with a [module.mcu] block in config.toml.

Unlike the other modules, this one needs a service to talk to: at least one
[mediaserver.pool.<name>] entry pointing at a reachable `mediaserver` process. The
address announced in the SDP is that server's own setting (`--public-ip`), never
kelixip's. Installing the package is not enough to make a conference work.

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

# script_dir — the reference scenario scripts. Installed here in one go; the %files
# lists below decide which package each ends up in. A script is reference material
# an operator derives from and is inert until a domains.toml rule names it, so the
# ones that drive a module-less core stay with the core. The mcu scripts do not:
# they are unusable without kelixip-mod-mcu (every conference verb they call is the
# module's), so they travel with it — see %files mod-mcu.
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
# The core owns script_dir itself, so mod-mcu can drop its scripts in without
# either package claiming the directory twice.
%dir %{_datadir}/%{name}
%{_datadir}/%{name}/*.exs
%exclude %{_datadir}/%{name}/mcu*.exs
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

# Each module ships its own document: what the docs on a host describe is then what
# that host can actually do. The .beam globs keep their trailing wildcard — a module
# is one named module plus its implementation (Registrar.Contact, Mcu.Client,
# Mcu.Adapter.Conn, …), and shipping only the named one installs a module whose every
# call fails.
%files mod-registrar
%doc doc/modules/registrar.md
%{kelixdir}/modules/Elixir.Kelix.Mod.Registrar*.beam

%files mod-auth_db
%doc doc/modules/auth_db.md
%{kelixdir}/modules/Elixir.Kelix.Mod.AuthDb*.beam

%files mod-mcu
%doc doc/modules/mcu.md doc/modules/mcu_module_guide.md
%{kelixdir}/modules/Elixir.Kelix.Mod.Mcu*.beam
# The reference conference scripts. They call the module's verbs and nothing else
# provides them, so a host that has them can run them.
%{_datadir}/%{name}/mcu*.exs

%changelog
* Tue Aug 18 2026 Emmanuel BUU <emmanuel.buu@ives.fr> - 1.5.0-1
- Service building blocks: an FSL scenario can enter a reusable sub-machine on its
  own legs and return from it with one event (sbb_fsm, sbb_return, use SIP.SBB).
- SBB.Call ships the first two: call/1 establishes the outbound leg — provisionals,
  serial hunt, the cancel race, the ACK — and bridge/1 relays the established call.
  The reference scripts lost the states they copied: direct-call.exs 230 -> 124
  lines, with auth 310 -> 199, with media 494 -> 310.
- bridge/1 can keep the caller when the callee hangs up
  (on_callee_hangup: :keep_caller), which is what turns a relay into a service.
- BREAKING: sub_fsm is renamed spawn_fsm, and the inter-FSM messages are renamed
  after their direction: {:parent_msg, ...}, {:child_msg, ...}, {:child_exit, ...}.
  The macro keeps a deprecated alias; the MESSAGES do not, and a scenario still
  matching the old shapes is warned about at compile time.
- b2bua.exs is deleted: it was a copy of direct-call.exs.
- User-Agent is now Kelixip/1.5.0.
* Tue Aug 18 2026 Emmanuel BUU <emmanuel.buu@ives.fr> - 1.4.1-1
- The scenario language is named the Finite State Language (FSL); DSL.md becomes
  FSL.md.
- FSL gains `stay` (handle an event without re-entering the state) and `goto back`
  (return to the previous state).
- An `on_events` `after` is now the deadline of the whole wait: `stay` does not
  re-arm it.
- Reference scripts updated: nine states removed, and registrar.exs loses
  wait_auth_register.
- User-Agent is now Kelixip/1.4.1.

* Fri Aug 14 2026 Emmanuel BUU <emmanuel.buu@ives.fr> - 1.4.0-1
- Version bump to 1.4.0: the media relay validated in real traffic. Cross-leg
  codec selection, per-leg codecs with real transcoding (VP8 <-> H.264), AV1,
  bidirectional NAT latching, media watchdog armed at answer.
- SIP correctness: URI parameters serialized in angle brackets, the Contact
  identity carried across the B2BUA, Route no longer echoed in responses, one
  single BYE per hangup, fresh Via branch on the ACK of a 2xx.
- User-Agent is now Kelixip/1.4.0.

* Mon Aug 10 2026 Emmanuel BUU <emmanuel.buu@ives.fr> - 1.3.0-1
- Version bump to 1.3.0: the B2BUA release. A scenario can now terminate an
  incoming call and place a second one of its own, relaying between the two.
- Call forwarding to a registered subscriber, serial and parallel hunting over
  an AOR's devices, dynamic target providers and SRV failover.
- A media server can be put in the middle of the two legs: one media session,
  two endpoints, transcoding on demand, and re-offers read before being relayed.
- Offer profiles: a callee refusing WebRTC is offered RTP/AVPF, then RTP/AVP,
  before the next device is tried.
- registrar: new targets/2 returning where to call an AOR, as a B2BUA peer.
- Resilience: a transaction timeout, a dead socket or a lost media server is
  reported to the scenario instead of leaving it waiting.

* Sat Aug 08 2026 Emmanuel BUU <emmanuel.buu@ives.fr> - 1.2.1-1
- Version bump to 1.2.1: the interoperability release. WebRTC calls proven
  with MS Edge and Chrome, and with Linphone 6.2.0 in SDES as well as DTLS.
- Codec negotiation fully delegated to the medooze media server; AV1 support,
  H.264 packetization-mode tolerance, realtime text over WebSocket.
- kelixip: scenario configurations are prechecked at boot and reload; a refused
  reload leaves the running configuration untouched. systemctl reload supported.
- New kelictl reload-all to reload every configured domain.

* Sun Aug 02 2026 Emmanuel BUU <emmanuel.buu@ives.fr> - 1.2.0-1
- Version bump to 1.2.0.
- New subpackage kelixip-mod-mcu: the conference mixer (design P6).

* Wed Jul 29 2026 Emmanuel BUU <emmanuel.buu@ives.fr> - 1.1.0-1
- Version bump to 1.1.0.

* Tue Jul 28 2026 Emmanuel BUU <emmanuel.buu@ives.fr> - 0.2.0-1
- First packaged release (design P10): core + mod-registrar + mod-auth_db
  subpackages, systemd unit with graceful-shutdown ExecStop, per-host cookie.

# kelixip.spec — Alma Linux 9 (design docs/design/DESIGN-KELIXIP.md §12).
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
Version:        1.6.1
# Counts the builds of this Version, and must be bumped for each one that leaves this
# machine: rpm identifies a package by its NEVRA, so installing over an
# already-installed one is a no-op — the host keeps the older payload while rpm -q
# reports the version you expected. Back to 1 when Version changes (CLAUDE.md).
Release:        2%{?dist}
Summary:        kelixip SIP application server
License:        BSL-1.1
URL:            https://github.com/neutrino38/elixip
Source0:        %{name}-%{version}.tar.gz
ExclusiveArch:  x86_64 aarch64

BuildRequires:  systemd-rpm-macros
Requires(pre):  shadow-utils
%{?systemd_requires}
# SELinux file contexts, set in %post. Hard requirements, not conditional: Alma 9
# is Enforcing out of the box, and without the labelling the service does not
# start at all (see %post) — a soft dependency would turn that into a silent
# failure at the first install on a minimal host.
Requires(post):   policycoreutils, policycoreutils-python-utils
Requires(postun): policycoreutils-python-utils
# The kelictl completion is data the shell reads, so the server runs without it and
# this stays WEAK: a minimal host may refuse it and still install. A default
# `dnf install` pulls it in, which is the point — on a host that lacks it, TAB is
# silently inert and nothing says why.
Recommends:     bash-completion

%description
kelixip is a SIP application server: declarative per-domain dispatch (config.toml
+ domains.toml) onto scenario scripts, a REST/CLI control surface (kelictl), and
Prometheus metrics.

The core ships NO SIP function. The registrar, the authentication back-end, the
conference mixer and the presence collection are loadable modules delivered as
separate packages (kelixip-mod-registrar, kelixip-mod-auth_db, kelixip-mod-mcu,
kelixip-mod-presence, kelixip-mod-mcu_presence, kelixip-mod-dialog_state) which
drop their bytecode into the
root-owned module directory; a deployment installs only what it uses.

This package embeds its own Erlang runtime — no system Erlang or Elixir is needed.

%package mod-registrar
Summary:        Registrar / user-location module for kelixip
Requires:       %{name} = %{version}

%description mod-registrar
The usrloc store: per-domain contact bindings with NAT/flow handling (received,
flow, Path), expiry bounds and the save/lookup/subscribe facade the registrar
scripts drive. Enable it with a [module.registrar] block in domains.toml.

%package mod-auth_db
Summary:        Database authentication module for kelixip
Requires:       %{name} = %{version}

%description mod-auth_db
Digest authentication against a MariaDB/MySQL subscriber table (kamailio-compatible
ha1/ha1b columns): it owns the challenge/accept/reject decision, the scripts only
compose the SIP response. Enable it with a [module.auth_db] block in config.toml.

%package mod-mcu
Summary:        Conference mixer (MCU) module for kelixip
Requires:       %{name} = %{version}

%description mod-mcu
Audio/video/text conferencing: conferences addressed by DID, a mixed audio leg and
a video mosaic per participant, driven over the Medooze MCU XML-RPC API, with the
REST/CLI surface (conference.*, participant.*, recording.*, slot.*) to inspect and
steer a live mix. Enable it with a [module.mcu] block in config.toml.

Unlike the other modules, this one needs a service to talk to: at least one
[mediaserver.pool.<name>] entry pointing at a reachable `mediaserver` process. The
address announced in the SDP is that server's own setting (`--public-ip`), never
kelixip's. Installing the package is not enough to make a conference work.

%package mod-presence
Summary:        Presence collection module for kelixip
Requires:       %{name} = %{version}

%description mod-presence
The presence collection (RFC 3856 / RFC 3903): the published state of each
presentity with its entity-tag, the live subscriptions to it, and the fan-out that
turns one PUBLISH into one NOTIFY per watcher. Its records are kamailio's
presentity and active_watchers rows, held in memory. Enable it with a
[module.presence] block in config.toml, and declare the packages a domain serves
with [[domain.presence]] blocks in domains.toml.

Who may watch whom is NOT decided here: the reference scripts are, and that is
where a deployment writes its rule.

%package mod-mcu_presence
Summary:        Conference rooms as presentities, for kelixip
Requires:       %{name} = %{version}
Requires:       %{name}-mod-mcu = %{version}
Requires:       %{name}-mod-presence = %{version}

%description mod-mcu_presence
The link between the conference mixer and the presence collection: each
conference room is a presentity, sip:<did>@<domain>, open while it runs, open and
busy when it is full, closed while its media server is lost. A watcher subscribes
to a room alone or in its buddy list, as it would to a user. Enable it with a
[module.mcu_presence] block in config.toml, next to [module.mcu] and
[module.presence].

%package mod-dialog_state
Summary:        Call occupancy of the served users, for kelixip
Requires:       %{name} = %{version}
Requires:       %{name}-mod-presence = %{version}

%description mod-dialog_state
The call state of each served user, reported to the presence collection: a BLF
key subscribed with Event: dialog (RFC 4235) lights while its user rings or
talks, a presence watcher sees on-the-phone while a call is up, and an ACD is
pushed every transition. Only a call whose party is proven a user of the domain
counts: authenticated by digest, or reached through its registrations. Enable
it with a [module.dialog_state] block in config.toml, next to [module.presence].

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

# Shell completion for kelictl. Inert without the bash-completion package, hence a
# weak dependency only: the file is data, loaded by basename when the operator types.
install -D -m 0644 completion/kelictl \
    %{buildroot}%{_datadir}/bash-completion/completions/kelictl

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
# SELinux: make the launchers a domain entry point.
#
# The release lives under %{_prefix}/lib, so every file in it is labelled `lib_t`,
# which entry-points no domain: systemd (`init_t`) execs bin/kelixip and the BEAM
# stays in `init_t`, where the Erlang distribution's own listen socket is denied
# (`Protocol 'inet_tcp': register/listen error: eacces`, and the node exits). Only
# the two `bin` directories are relabelled: `bin_t` is what `init_t` transitions to
# `unconfined_service_t` from. The ERTS shared objects must stay `lib_t`.
for _re in "%{kelixdir}/bin(/.*)?" "%{kelixdir}/erts-[^/]+/bin(/.*)?"; do
    semanage fcontext -a -t bin_t "$_re" 2>/dev/null || semanage fcontext -m -t bin_t "$_re" || :
done
restorecon -R %{kelixdir}/bin %{kelixdir}/erts-*/bin || :

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
    for _re in "%{kelixdir}/bin(/.*)?" "%{kelixdir}/erts-[^/]+/bin(/.*)?"; do
        semanage fcontext -d "$_re" 2>/dev/null || :
    done
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
# The two completion directories are owned here as well as by the bash-completion
# package, which we do not require: shared ownership is legal, an unowned directory
# left behind by an erase is not.
%dir %{_datadir}/bash-completion
%dir %{_datadir}/bash-completion/completions
%{_datadir}/bash-completion/completions/kelictl
# The core owns script_dir itself, so mod-mcu can drop its scripts in without
# either package claiming the directory twice.
%dir %{_datadir}/%{name}
%{_datadir}/%{name}/*.exs
%exclude %{_datadir}/%{name}/mcu*.exs
%exclude %{_datadir}/%{name}/presence-*.exs
%exclude %{_datadir}/%{name}/registrar-presence.exs
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
# Mcu and Mcu.* — not Mcu*, which would take McuPresence from its own package.
%{kelixdir}/modules/Elixir.Kelix.Mod.Mcu.beam
%{kelixdir}/modules/Elixir.Kelix.Mod.Mcu.*.beam
# The reference conference scripts. They call the module's verbs and nothing else
# provides them, so a host that has them can run them.
%{_datadir}/%{name}/mcu*.exs

%files mod-presence
%doc doc/modules/presence.md
%{kelixdir}/modules/Elixir.Kelix.Mod.Presence*.beam
# The reference scripts: one per method, plus the list server of RFC 4662 and
# the registrar that reports registrations as presence. They call this module's
# verbs and nothing else provides them.
%{_datadir}/%{name}/presence-*.exs
%{_datadir}/%{name}/registrar-presence.exs

%files mod-mcu_presence
%doc doc/modules/mcu_presence.md
%{kelixdir}/modules/Elixir.Kelix.Mod.McuPresence*.beam

%files mod-dialog_state
%doc doc/modules/dialog_state.md
%{kelixdir}/modules/Elixir.Kelix.Mod.DialogState*.beam

%changelog
* Sun Sep 27 2026 Emmanuel BUU <emmanuel.buu@ives.fr> - 1.6.1-1
- kelescope shows presence live: Kelix.Control.subscribe_presence/2 returns a
  domain's presentities, then pushes each change.
- kelictl presence list shows a presentity reported registered by
  registrar-presence.exs, as a state of source "registrar"; list and show gain
  the source and status columns.
- The registrar no longer renders an AOR's detail on every REGISTER when no
  registrations panel is open on its domain.
- New subpackage kelixip-mod-mcu_presence: a conference room is a presentity
  (open, busy when full, closed while its media server is lost).
- presence-subscribe.exs answers noresource to a presentity with no state,
  instead of closed.
- BLF keys: the dialog event package (RFC 4235) is served, with Event: dialog
  in a [[domain.presence]] block. New subpackage kelixip-mod-dialog_state
  reports each served user's calls to it, and on-the-phone to presence.
- presence-publish.exs answers 403 to a PUBLISH about another user's state, and
  both presence scripts log whose state changed to what.
- A notifier whose script ends keeps retransmitting its final NOTIFY, and one
  whose script dies sends it (deactivated) instead of leaving the watcher
  subscribed.
- User-Agent is now Kelixip/1.6.1.

* Sun Sep 27 2026 Emmanuel BUU <emmanuel.buu@ives.fr> - 1.6.0-9
- A scenario state that raises tears down what it had set up: teardown now runs
  on the context the failing state had built, so both legs and the media session
  are released and the caller can hang up.
- A dialog monitors its application and ends with it, hung up first when there is
  a session to end, instead of answering 503 to every later in-dialog request.

* Sat Sep 26 2026 Emmanuel BUU <emmanuel.buu@ives.fr> - 1.6.0-8
- Presence now follows real registrations. The registrar-presence.exs script read
  the REGISTER's To as a parsed URI, which only a test request carries: presence
  was never told of a registration (no NOTIFY to watchers), and the script ended
  1 ms after its 200 OK. Every later REGISTER of that client went unanswered and
  timed out 408.
- A REGISTER dialog ends with its registrar session, so the client's next
  REGISTER reaches a live one instead of timing out 408.
- kelictl: module commands take positional arguments, bound in order to the
  arguments the command declares — kelictl presence list weshwesh.eu.

* Sat Sep 26 2026 Emmanuel BUU <emmanuel.buu@ives.fr> - 1.6.0-7
- List NOTIFYs are deflated as soon as the body passes 500 octets, when the
  watcher accepts it. The bound was 1200 for the body alone, which ignored the ~700
  octets of headers a list NOTIFY carries over IPv6: a three-entry list went out
  clear in a 1806-octet datagram, which the path fragmented and the watcher never
  received.

* Sat Sep 26 2026 Emmanuel BUU <emmanuel.buu@ives.fr> - 1.6.0-6
- Presence follows registrations: a new reference script, registrar-presence.exs
  (shipped with kelixip-mod-presence), is registrar.exs plus a report to the
  presence collection on every change. A subscriber that does not PUBLISH is open
  while one of its devices is registered and closed when the last one goes —
  un-REGISTER, connection lost, or a registration that lapsed — and its watchers
  are NOTIFYed on each change. A refused refresh no longer ends the session.
- A list subscription reports an unpublished subscriber of a registrar domain as
  open or closed, not noresource; noresource is kept for unknown users and for
  domains with no registrar or not served.
- kelictl registration remove and DELETE /domains/<domain>/registrations/<aor>
  update presence when kelixip-mod-presence is loaded.
- Registrar fix: an Expires: 0 now removes only the contacts it names (RFC 3261
  §10.3). It used to remove every binding of the AOR, un-registering a
  subscriber's other devices whenever one of them signed off.

* Tue Sep 22 2026 Emmanuel BUU <emmanuel.buu@ives.fr> - 1.6.0-2
- Buddy lists (RFC 4662 / RFC 5367): kelixip-mod-presence ships a third
  reference script, presence-rls.exs, which serves a list subscription. Declare
  the list URI the client sends (sip.linphone.org for Linphone) as a domain of
  its own, served by that script.
- The presence scripts are no longer also claimed by the core package: they
  belong to kelixip-mod-presence alone, as the mcu scripts belong to
  kelixip-mod-mcu.

* Sat Sep 19 2026 Emmanuel BUU <emmanuel.buu@ives.fr> - 1.5.5-2
- Rebuild only: the 1.5.5-1 changelog listed the WSS hardening alone, written
  before the rest of the release landed. No code change.

* Fri Sep 18 2026 Emmanuel BUU <emmanuel.buu@ives.fr> - 1.6.0-1
- Presence (RFC 6665 / 3856 / 3903): SUBSCRIBE, PUBLISH and the NOTIFYs between
  them. New subpackage kelixip-mod-presence — the collection, the entity-tags and
  the fan-out — with the reference scripts presence-subscribe.exs and
  presence-publish.exs.
- domains.toml: [[domain.presence]] is now an array of tables, ONE PER EVENT
  PACKAGE, each naming its subscribe and publish script. A single
  [domain.presence] table is refused: replace it with a block carrying
  event-package = "presence". A package a domain declares none for is answered
  489, with Allow-Events naming the ones it serves.
- An out-of-dialog MESSAGE is no longer routed to the presence function: it
  carries no Event and page-mode chat is a function of its own. It is answered
  405 until [[domain.chat]] lands.
- OPTIONS now advertises what this server implements: INVITE, ACK, CANCEL, BYE,
  SUBSCRIBE, PUBLISH and NOTIFY join REGISTER and OPTIONS in Allow.
- The Finite State Language leaves the tree: it is now the separate package
  finite_state_language (OTP app :fsl, Apache-2.0), and SIP plugs into it through
  SIP.FSL.Host. Scripts keep the names they use: SIP.Scenario and the other SIP
  names stay, as facades over FSL.*.
- The live-monitor registry is registered as FSL.Monitor, and pushes
  {:fsl_monitor, ...}.
- User-Agent is now Kelixip/1.6.0.

* Tue Sep 15 2026 Emmanuel BUU <emmanuel.buu@ives.fr> - 1.5.5-1
- sip: an INVITE server transaction no longer carries timer F. A call that rang
  longer than 32 s was ended with a 408 to the caller while the callee was still
  ringing. How long a phone rings is the application's decision (RFC 3261
  §17.2.1); the remaining bound is :sip_timer_ist_ringing, 600 000 ms.
- sip: when the stack answers 408 for a silent application, the application is
  told. A B2BUA now CANCELs the callee still ringing for a call nobody can take.
- sip: a 183 with no body no longer raises inside the server transaction, which
  used to take the dialog and the whole call with it.
- b2bua: early media, as the `early_media:` option of the media mode, off by
  default. A gateway's announcement and the network ringback are audible while
  the callee rings. A media path that cannot be built CANCELs the attempt
  instead of relaying a call that can never carry anything.
- mcu: a text medium (T.140 over WebSocket) no longer fails the bridge it is
  part of. EndpointSetRTPProperties only knows audio and video, and its refusal
  killed a whole total conversation call.
- sip: P-Asserted-Identity is read as a whole URI, display name kept, and the
  two comma-separated values of RFC 3325 §9.1 are read apart.
- sip: a URI built field by field, as a routing script writes one, gets its
  scheme's default port. Such a destination used to travel portless and the
  INVITE never went out.
- sip: a received request is marked with the transport it came in over.
- kelixip: a domain alias written `*.suffix` routes every host below that
  suffix. A literal name wins over a wildcard, the longest suffix wins among
  wildcards, and a `*` written anywhere else rejects the file.
- kelixip: a routing refusal says why, naming the request and the domains.toml
  block that is missing.
- WSS: the WebSocket layer is hardened. What a fragmented message accumulates is
  bounded, so a peer can no longer grow a connection's memory without end.
- The unused dependency on socket is dropped; socket2 carries the whole WebSocket
  path.
- User-Agent is now Kelixip/1.5.5.

* Thu Sep 10 2026 Emmanuel BUU <emmanuel.buu@ives.fr> - 1.5.4-1
- mcu: the module pushes its events to kelixip, so a supervision view is told what
  a conference and its legs do rather than polling for it.
- SBB bridge(): the outbound leg is disconnected cleanly during a progressive
  shutdown, instead of being left to time out.
- sip: what the depacketizer accumulates is bounded, and a malformed header value
  no longer raises.
- sip: an oversized message is answered 513 rather than silently dropped.
- Packaging: bash-completion is declared as an optional dependency.
- User-Agent is now Kelixip/1.5.4.

* Tue Sep 08 2026 Emmanuel BUU <emmanuel.buu@ives.fr> - 1.5.3-1
- Registrations are observable live: Kelix.Control.registrations/0,
  registrations/1 and registration/2 read the registrar's bindings per domain, and
  subscribe_registrations/2 pushes every change of a domain as it happens. What
  kelescope displays, it is told; it does not poll.
- registrar: a binding taken, renewed or dropped is published as an event, so a
  supervision view and the node agree without either re-deriving the REGISTER.
- mcu: a conference and its legs publish the same kind of events, for the same view.
- User-Agent is now Kelixip/1.5.3.

* Sun Sep 06 2026 Emmanuel BUU <emmanuel.buu@ives.fr> - 1.5.2-7
- Packaging: Release 6 was built more than once with different payloads, so dnf took
  the second install for a package it already had and kept the first — a node ran a
  controller without the T.140 data channel while rpm reported the version that has
  it. Hence this 7, and the rule written next to Release:.
- Packaging: the release tree is rebuilt from scratch, so a package carries one
  elixip2 and one releases/<version> instead of every version ever built here.

* Sun Sep 06 2026 Emmanuel BUU <emmanuel.buu@ives.fr> - 1.5.2-1
- Multi-interface: a node speaks IPv4 and IPv6 at once, on an internal side and a
  public side. Three new [[listen]] keys, all optional: tag (internal / public) and
  networks say which side a listener sits on, advertise names the public face of addr
  for a 1:1 NAT. addr accepts an IPv6 address, and absent it binds both families,
  one socket each.
- Multi-interface: UDP is one socket per family and the selector picks by
  destination. A second udp entry of a family already bound is ignored with a warning.
- Multi-interface: advertise is not a flat substitution — a public peer gets the
  alias, an internal peer the bound address, in the Via, the Contact and the SDP.
  addr must be explicit and of the same family, or the boot is refused.
- Multi-interface: each media leg is placed on the media server's addressing profile
  matching its own side, and the B2BUA resolves and marks every target before asking
  the pool for a server carrying all the profiles in play.
- mcu: an IPv6-only conference interoperates with Chrome. A call whose family the
  media server does not carry is refused rather than answered with an unreachable
  address.
- mcu: Mcu.SBB.conference() publishes a conference leg's whole life as a service
  building block — the ACK sequence and its retransmissions, INFO, the RFC 5168
  frame requests, the BYE ordering, and a silent leg hung up.
- mcu: real-time text on a WebRTC data channel (RFC 8865), for a conference leg as
  well as a B2BUA leg. It is what our own offers carry by default on a WebRTC leg,
  a browser having no m=text.
- FIX: mcu hold and resume — a hold is a sendrecv -> sendonly transition, so a hold
  longer than 10 s no longer kills an audio-only leg through the RTP watchdog.
- FIX: mcu no longer restarts ICE on every renegotiation, which kept a peer from
  leaving a hold.
- FIX: H.264 selection prefers the main profile and packetization mode 1 when the
  caller advertises several.
- SECURITY: the outbound TLS and WSS legs verify the certificate they are offered.
  New [tls] section, verify off by default — verifying supposes an authority agreed
  with the peer. The name checked is the SIP domain of the URI, never the resolved
  address (RFC 5922).
- auth_db: PostgreSQL as a second driver of the subscriber table
  (driver = "postgres"). mysql remains the default.
- FIX: SBB.authenticate(realm: "...") uses the option passed instead of ignoring it;
  the entry options of every service building block now reach the block.
- kelictl mediaserver show displays what the media server answers about itself
  (GET /status/general): version, real codec capabilities, text transports,
  encryption, addressing profiles, load. mediaserver list gains a version column.
  Asked, never declared.
- kelictl monitor continuous: the monitor view redrawn live, without polling.
- A B2BUA call can be recorded on both legs at once (media_record(leg: :outbound)),
  one file per leg.
- SELinux on Alma Linux 9: the post-install labels the launcher directories bin_t,
  without which the node exited at boot on "register/listen error: eacces".
- Medooze mediaserver 1.14.0 is required.
- User-Agent is now Kelixip/1.5.2.
* Thu Aug 20 2026 Emmanuel BUU <emmanuel.buu@ives.fr> - 1.5.1-1
- mcu: the conference DEFINITIONS survive a node restart, in one JSON file named by
  [module.mcu] conference_file. Only rooms somebody declared are written; a restored
  room is rebuilt by the same path that recovers one after a media-server restart.
  A file that does not parse disables persistence rather than being overwritten.
- mcu: a conference may name the video codec it states FIRST in its answers
  (preferred_video_codec). A preference and not a codec list: it moves a payload type
  the caller offered AND the media server accepted, and a miss is logged per leg
  naming which of the two dropped it.
- mcu: admit() wires the leg it admits — local identity, connection options and the
  media server the conference is pinned to — so no script states that plumbing.
- FIX: an offerless UPDATE (the RFC 4028 session-timer refresh) is answered with a
  bare 200 on the leg it arrived on instead of ending the call. Clients refresh every
  45 s, so this cost long calls.
- FIX: a REGISTER refresh arriving on a new connection prolongs its registration
  instead of opening a second registrar session.
- FIX: WSS ping/pong keep-alive, so an idle WebSocket is not dropped in the middle.
- [mediaserver] video_bitrate is one key per node for both media paths, replacing two
  compiled-in defaults (800 and 1024 kb/s) no operator could reach. bitrate_feedback
  narrows which RTCP bitrate-feedback dialects are answered; transport_cc negotiates
  transport-wide congestion control, off by default.
- BREAKING: conference video defaults change — video_fps 15 -> 30, video_bitrate
  1024 -> 1500 kb/s. The mosaic canvas and the encoded size are held equal.
- User-Agent is now Kelixip/1.5.1.
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

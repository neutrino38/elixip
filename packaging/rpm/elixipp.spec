# elixipp.spec — the SIP test-tool escript (BUILD.md § elixipp, ELIXIPP.md).
#
# The payload is PRE-BUILT: Source0 is the staged tarball produced by
# packaging/stage-elixipp.sh (a `mix escript.build` output). Unlike kelixip's
# release, the escript is pure BEAM bytecode — no embedded ERTS, no native code —
# so it does not need to be assembled on the target OS; it only needs a matching
# Erlang/OTP runtime to run. See packaging/README.md.
#
#   rpmbuild -bb --define "_topdir <dir>" packaging/rpm/elixipp.spec

Name:           elixipp
Version:        1.6.3
Release:        2%{?dist}
Summary:        SIP scenario test tool driven by the Finite State Language
License:        BUSL-1.1
URL:            https://github.com/neutrino38/elixip
Source0:        %{name}-%{version}.tar.gz
BuildArch:      noarch

# escript needs an Erlang runtime; :logger/:inets/:crypto are elixip2's declared
# extra_applications (apps/elixip2/mix.exs). Elixir's own stdlib travels inside the
# escript (mix escript.build embeds it) — only the OTP applications it calls into
# still have to come from the host.
Requires:       erlang-erts, erlang-kernel, erlang-stdlib, erlang-crypto, erlang-inets

%description
elixipp is a SIP scenario test tool — a sipp-like replacement driven by the Finite
State Language (FSL): signaling over SIP/UDP/TCP/TLS/WSS, and able to drive a media
server to fully simulate SIP calls (registration, calls, WebRTC).

This package ships the escript alone: a self-contained BEAM bytecode archive that
needs only an Erlang/OTP runtime, no Elixir installation.

%prep
%setup -q

%build
# Nothing to build: Source0 carries the pre-built escript (see packaging/README.md).

%install
rm -rf %{buildroot}
install -D -m 0755 bin/elixipp %{buildroot}%{_bindir}/elixipp

%files
%doc doc/ELIXIPP.md doc/FSL.md
%{_bindir}/elixipp

%changelog
* Tue Oct 06 2026 Emmanuel BUU <latribuu@proton.me> - 1.6.3-2
- Released together with kelixip 1.6.3-2.
- RFC 4028 session timers in the dialog layer, off by default
  (config :elixip2, :session_timer): scenarios send and answer what they did
  before unless they enable them.

* Sat Oct 03 2026 Emmanuel BUU <latribuu@proton.me> - 1.6.3-1
- Released together with kelixip 1.6.3-1.
- PIDF: extension elements of <rpid:activities> are read and written as marks.
- User-Agent is now Elixipp-1.6.3.

* Wed Sep 30 2026 Emmanuel BUU <latribuu@proton.me> - 1.6.2-1
- Released together with kelixip 1.6.2-1.
- UAC.Page and UAS.Page: built-in page-mode MESSAGE scenarios, driven by
  --to, --body, --content-type, --expires, --count, --interval, --expect and
  --code.
- User-Agent is now Elixipp-1.6.2.

* Sun Sep 27 2026 Emmanuel BUU <latribuu@proton.me> - 1.6.1-1
- Released together with kelixip 1.6.1-1.
- User-Agent is now Elixipp-1.6.1.

* Sun Sep 27 2026 Emmanuel BUU <latribuu@proton.me> - 1.6.0-9
- A scenario state that raises tears down what it had set up: teardown now runs
  on the context the failing state had built, so both legs and the media session
  are released and the caller can hang up.
- A dialog monitors its application and ends with it, hung up first when there is
  a session to end, instead of answering 503 to every later in-dialog request.
- elixipp: the live monitor display is corrected, and a scenario may play and
  record on the same leg at once.
- elixipp: WebSocket text client leg (text_transport: :ws).

* Sat Sep 26 2026 Emmanuel BUU <latribuu@proton.me> - 1.6.0-8
- Rebuild, released together with kelixip 1.6.0-8 (a REGISTER dialog ends
  with its registrar session).

* Sat Sep 26 2026 Emmanuel BUU <latribuu@proton.me> - 1.6.0-7
- List NOTIFYs are deflated as soon as the body passes 500 octets, when the
  watcher accepts it. The bound was 1200 for the body alone, which ignored the ~700
  octets of headers a list NOTIFY carries over IPv6: a three-entry list went out
  clear in a 1806-octet datagram, which the path fragmented and the watcher never
  received.

* Sat Sep 26 2026 Emmanuel BUU <latribuu@proton.me> - 1.6.0-6
- Rebuild, released together with kelixip 1.6.0-6.

* Fri Sep 18 2026 Emmanuel BUU <latribuu@proton.me> - 1.6.0-1
- The Finite State Language leaves the tree: it is now the separate package
  finite_state_language (OTP app :fsl, Apache-2.0). Scenarios keep the names they
  use: SIP.Scenario stays the facade a scenario uses.
- User-Agent is now Elixipp-1.6.0.

* Sat Sep 19 2026 Emmanuel BUU <latribuu@proton.me> - 1.5.5-2
- Rebuild only: the 1.5.5-1 changelog listed the WSS hardening alone, written
  before the rest of the release landed. No code change.

* Tue Sep 15 2026 Emmanuel BUU <latribuu@proton.me> - 1.5.5-1
- sip: an INVITE server transaction no longer carries timer F, which ended every
  call ringing longer than 32 s with a 408 to the caller. The remaining bound is
  :sip_timer_ist_ringing, 600 000 ms.
- sip: when the stack answers 408 for a scenario that did not reply, the scenario
  is told, so it can end the leg it opened.
- sip: a 183 with no body no longer raises inside the server transaction.
- sip: P-Asserted-Identity is read as a whole URI, display name kept, and the two
  comma-separated values of RFC 3325 §9.1 are read apart.
- sip: a URI built field by field gets its scheme's default port; it used to
  travel portless and the request never went out.
- sip: a received request is marked with the transport it came in over.
- b2bua: early media, as the `early_media:` option of the media mode, off by
  default.
- WSS: the WebSocket layer is hardened — the shared stack, so the tool gets it too.
  What a fragmented message accumulates is bounded.
- The unused dependency on socket is dropped.
- User-Agent is now Elixipp-1.5.5.

* Thu Sep 10 2026 Emmanuel BUU <latribuu@proton.me> - 1.5.4-1
- sip: what the depacketizer accumulates is bounded, and a malformed header value
  no longer raises — the shared stack, so the tool gets it too.
- sip: an oversized message is answered 513 rather than silently dropped.
- User-Agent is now Elixipp-1.5.4.

* Tue Sep 08 2026 Emmanuel BUU <latribuu@proton.me> - 1.5.3-1
- The escript follows the umbrella version; nothing changed in the tool itself.
- User-Agent is now Elixipp-1.5.3.
* Sun Sep 06 2026 Emmanuel BUU <latribuu@proton.me> - 1.5.2-1
- Multi-interface: a scenario reads and writes IPv6 addresses in SIP messages, and
  a UAC leg binds the family of the address it dials.
- The outbound TLS and WSS legs verify the certificate they are offered when
  :tls_verify is on; the name checked is the SIP domain of the URI (RFC 5922).
- Real-time text on a WebRTC data channel (RFC 8865), offered by default on a
  WebRTC leg; text_transport: :rtp asks for m=text instead.
- A B2BUA call can be recorded on both legs at once (media_record(leg: :outbound)),
  one file per leg; media_leg_of/1 says which leg an :ms_event belongs to.
- User-Agent is now Elixipp-1.5.2.
* Sat Aug 22 2026 Emmanuel BUU <latribuu@proton.me> - 1.5.1-1
- First packaged release of the elixipp escript.

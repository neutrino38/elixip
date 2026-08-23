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
Version:        1.5.2
Release:        1%{?dist}
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
* Sat Aug 22 2026 Emmanuel BUU <emmanuel.buu@ives.fr> - 1.5.1-1
- First packaged release of the elixipp escript.

# Building elixip / elixipp / kelixip

This repository is a **Mix umbrella** with four apps under `apps/`:

| App | Kind | Artifact | Depends on |
|-----|------|----------|------------|
| `elixip2` | library | — (shared SIP stack + DSL + media) | — |
| `elixipp` | test tool | **escript** `elixipp` | `elixip2` |
| `kelixip` | SIP server | **OTP release** `kelixip` (+ `kelictl`) | `elixip2` |
| `kelix_modules` | loadable modules | **`.beam` files** for `module_dir` | `kelixip` |

Each app pulls only its own dependencies, so the `elixipp` escript never carries
the server's HTTP/DB stack, and vice-versa. The library app is named `:elixip2`
(kept as-is to avoid churn on its many config references); its directory is
`apps/elixip2`. Design rationale: [docs/design/kelixip_basic_design.md](docs/design/kelixip_basic_design.md) §12.0.

## Prerequisites

- **Erlang/OTP** (the BEAM runtime) — required for everything.
- **Elixir** (`mix`) — required to build; **not** required at runtime for the
  `elixipp` escript (only the Erlang runtime is), and embedded in the `kelixip`
  release (ERTS is bundled).

## Common tasks (from the repo root)

All apps share the root `deps/`, `mix.lock` and `_build/`.

```bash
mix deps.get      # fetch dependencies for all apps
mix compile       # compile all apps
mix format        # format the whole tree
mix test          # run every app's test suite
```

### Running the tests

```bash
mix test                      # everything
mix test --exclude live       # skip tests needing outbound network (a real SIP proxy)
mix test apps/elixip2/test/sip_parser_test.exs        # one file
mix test apps/elixip2/test/sip_parser_test.exs:42     # one test by line
```

Notes:

- Test file paths live under `apps/<app>/test/`. In the umbrella, each app's
  tests run from **that app's directory**, so fixtures loaded with cwd-relative
  paths (`File.read("test/SIP-…")`, `scenarios/…`, `certs/…`) resolve inside the
  app.
- A few tests are **order-dependent** (named singleton processes leak state
  across test files) and the `ScenarioIntegration` **media** tests are flaky
  under load. They pass when run in isolation — so the practical bar is
  "green in isolation", not a spotless full run.
- `:live` tests require outbound network to a real SIP proxy; exclude them where
  there is none.

## elixipp — the test-tool escript

```bash
cd apps/elixipp
mix escript.build            # produces apps/elixipp/elixipp (self-contained)
./elixipp --help
./elixipp ../elixip2/scenarios/uac_invite.exs      # run a scenario file
./elixipp --listen udp:5060 ../elixip2/scenarios/uas_register.exs   # server (UAS) mode
# The scenario path is taken as given, relative to the current directory.
```

The escript bundles the compiled BEAM of `elixipp` + `elixip2` + their deps into
one file; it still needs an Erlang runtime (`erl`/`escript`) on the host. Install
it on your `PATH` with `mix escript.install`, or just copy the binary.

Full usage — including `--config`, `--monitor`, server (UAS) mode and the JSON
account files — is in [ELIXIPP.md](ELIXIPP.md).

## kelixip — the server OTP release

```bash
cd apps/kelixip
MIX_ENV=prod mix release kelixip     # -> _build/prod/rel/kelixip/ (ERTS embedded)
```

Run it:

```bash
REL=_build/prod/rel/kelixip/bin/kelixip
$REL start        # foreground
$REL daemon       # background
$REL remote       # attach a remote shell to the running node
$REL rpc "EXPR"   # evaluate EXPR on the running node
$REL stop         # graceful stop
```

`kelictl` (the control CLI) ships **inside this release** as a `bin/` command
(it RPCs the running node) — it is not a separate escript. See
[docs/design/kelixip_basic_design.md](docs/design/kelixip_basic_design.md) §10.2, §12.

Point it at its configuration (design §2.1, §12.1):

```bash
KELIXIP_CONFIG=/etc/kelixip/config.toml \
KELIXIP_DOMAINS=/etc/kelixip/domains.toml $REL daemon
```

Both default to those FHS paths; an unreadable or invalid file aborts the boot and
says why on stderr.

> Status: the server boots, binds its `[[listen]]` ports, dispatches and answers
> (registrar), and ships as an **RPM** (Alma Linux 9) and a **deb**
> (Ubuntu/Debian) — both below. What is still missing for "basic" is the
> `radius_billing` module (design §15).

## kelix_modules — the loadable modules

The release carries **no SIP function**: `registrar` and `auth_db` are installed
as `.beam` files into `server.module_dir` and loaded per `[module.<name>]` block
(design §8.3, §16.12). `apps/kelixip` does not depend on this app, which is what
keeps them out of the release.

```bash
cd apps/kelix_modules
MIX_ENV=prod mix compile
# install where the server looks (default /usr/lib/kelixip/modules)
cp _build/prod/lib/kelix_modules/ebin/Elixir.Kelix.Mod.*.beam "$MODULE_DIR"/
```

On a packaged host this copy is what `dnf install kelixip-mod-registrar` (or
`apt install kelixip-mod-registrar`) does; the manual form above is for development,
where nothing rebuilds this app for you.

Check what a running node actually loaded with `kelictl status` (`modules:` line).
Installing a new version of a module is a copy plus `kelictl module reload <name>`
— no server restart.

## Building the RPM packages (Alma Linux 9)

Three packages come out of one `mix release`:

| Package | Contents |
|---|---|
| `kelixip` | the release (embedded ERTS) + `kelictl` + systemd unit + `/etc/kelixip` |
| `kelixip-mod-registrar` | the registrar module's `.beam`, for `module_dir` |
| `kelixip-mod-auth_db` | the auth_db module's `.beam`, for `module_dir` |

### The golden rule: build on the target OS

The release embeds ERTS (`include_erts: true`), and ERTS is **native code** — the
beam VM, `erl_child_setup`, `inet_gethost`, and the crypto NIF linked against
OpenSSL. It is dynamically linked to the **build host's** glibc / OpenSSL / ncurses,
so a release assembled on Debian or Alpine fails to load on Alma Linux 9 (which
ships glibc 2.34 + OpenSSL 3).

So: build on **AL9** — a real host, or the `almalinux:9` container below. Never in a
Docker Hub `hexpm/elixir:*` image; those are Debian/Alpine-based, and the embedded
ERTS would be theirs. (Rationale and the alternative Erlang sources:
[docs/design/kelixip_packaging.md](docs/design/kelixip_packaging.md).)

### Build-host toolchain

Only **Erlang** is OS-sensitive; Elixir is pure BEAM bytecode, so a precompiled zip
is fine. What follows is exactly how the reference build host is set up (verified
2026-07-28 on AlmaLinux 9.6).

**1) Erlang/OTP from EPEL.** EPEL 9 ships an AL9-native OTP 26 whose ERTS links this
system's OpenSSL 3 — which is the whole point. (EPEL does *not* ship Elixir.)

```bash
sudo dnf install -y epel-release
sudo dnf install -y erlang            # -> erlang-26.2.5-1.el9 as of 2026-07
erl -noshell -eval 'io:format("~s~n",[erlang:system_info(otp_release)]),halt().'
```

**2) Elixir by hand into `/opt/elixir`,** from the **`elixir-otp-26.zip`** asset —
matched to the OTP major installed above. Elixir is bytecode, but an artifact
compiled under OTP 27 can fail to load on an OTP-26 runtime, so the `otp-27` zip is
the wrong file here.

```bash
sudo dnf install -y unzip curl tar git
ELIXIR_VERSION=1.18.3
curl -fsSL -o /tmp/elixir.zip \
  "https://github.com/elixir-lang/elixir/releases/download/v${ELIXIR_VERSION}/elixir-otp-26.zip"
sudo mkdir -p /opt/elixir
sudo unzip -q -o -d /opt/elixir /tmp/elixir.zip     # -> /opt/elixir/{bin,lib,VERSION}

# On the PATH for every login shell
echo 'export PATH=/opt/elixir/bin:$PATH' | sudo tee /etc/profile.d/elixir.sh
sudo chmod 0644 /etc/profile.d/elixir.sh
export PATH=/opt/elixir/bin:$PATH                   # for the current shell

mix local.hex --force && mix local.rebar --force    # per user building
elixir --version                                    # Elixir 1.18.3 (compiled with Erlang/OTP 26)
```

> Elixir 1.15 → 1.18 all support OTP 26, and the project requires only
> `elixir: "~> 1.15"` with no OTP pin — 1.18.x is the version used in development.
> Check the current EPEL OTP ↔ Elixir `otp-XX` pair when you rebuild a host: the
> numbers above are a snapshot, not a permanent pin.

**3) rpmbuild.**

```bash
sudo dnf install -y rpm-build systemd-rpm-macros shadow-utils
```

### Build

```bash
mix deps.get                      # once, or let stage.sh do it
packaging/build-rpm.sh            # -> packaging/dist/*.rpm
```

`build-rpm.sh` runs `packaging/stage.sh` (which assembles the release with
`MIX_ENV=prod mix release kelixip`, compiles `apps/kelix_modules`, and packs both
plus the config/unit/doc inputs into `packaging/build/SOURCES/kelixip-<version>.tar.gz`),
then `rpmbuild -bb` on [`packaging/rpm/kelixip.spec`](packaging/rpm/kelixip.spec).
The version comes from `apps/kelixip/mix.exs`; the build **fails loudly** if the
spec disagrees, so bump both together.

Result:

```
packaging/dist/kelixip-1.1.0-1.el9.x86_64.rpm               7.1M   (release + ERTS)
packaging/dist/kelixip-mod-registrar-1.1.0-1.el9.x86_64.rpm  41K
packaging/dist/kelixip-mod-auth_db-1.1.0-1.el9.x86_64.rpm     26K
```

### Build in a container instead

No AL9 host, or a reproducible CI build:

```bash
packaging/build-in-container.sh    # needs podman or docker; same output in packaging/dist
```

It builds [`packaging/Containerfile.al9`](packaging/Containerfile.al9) — the same
toolchain as above, EPEL Erlang plus the `otp-26` Elixir zip — and runs
`build-rpm.sh` inside it. `_build` and `deps` get their own volumes (named per
target) so the container's OTP artifacts never mix with the host's.

### Install and verify on the target

```bash
sudo dnf install ./kelixip-*.rpm          # or rpm -ivh
sudo systemctl enable --now kelixip
kelictl status                            # listeners bound, modules loaded
curl -s http://127.0.0.1:9095/health
```

`config.toml` / `domains.toml` are `%config(noreplace)`: on upgrade your files stay
and the packaged versions land as `*.rpmnew`. What the packages install where, and
how to configure the service, is the operator's guide:
[docs/kelixip/installation.md](docs/kelixip/installation.md). What lives in
`packaging/` and why: [packaging/README.md](packaging/README.md).

## Building the deb packages (Ubuntu / Debian)

The same three packages, from the same `mix release` and the same
[`packaging/stage.sh`](packaging/stage.sh) staging step:

| Package | Contents |
|---|---|
| `kelixip` | the release (embedded ERTS) + `kelictl` + systemd unit + `/etc/kelixip` |
| `kelixip-mod-registrar` | the registrar module's `.beam`, for `module_dir` |
| `kelixip-mod-auth-db` | the auth_db module's `.beam`, for `module_dir` |

Two deliberate differences from the RPM, both distribution conventions:

- the environment file is **`/etc/default/kelixip`**, not `/etc/sysconfig/kelixip`
  (the unit declares both as optional `EnvironmentFile=`, and the release's
  `rel/env.sh` sources whichever exists, so `kelictl` still targets the right node);
- the auth_db package is **`kelixip-mod-auth-db`** — a Debian package name may not
  contain an underscore. The module's registered name is still `auth_db`, and the
  config block is still `[module.auth_db]`.

### The golden rule, deb flavour: one package per target release

Same reason as the RPM — the embedded ERTS is native code — with one extra
consequence: the core's `Depends` are **computed** from the build host by
`dpkg-shlibdeps`, so they name *that release's* library packages. Ubuntu 22.04 has
`libssl3`, 24.04 and later have `libssl3t64` (the 64-bit `time_t` transition). A deb
built on 24.04 therefore refuses to install on 22.04, which is the honest outcome:
build one deb per Ubuntu/Debian release you support.

### Build-host toolchain

Only **Erlang** is OS-sensitive; Elixir is pure BEAM bytecode, so a precompiled zip
is fine. (Verified 2026-07-29 on Ubuntu 26.04, OTP 27 + Elixir 1.18.3.)

**1) Erlang/OTP.** The distribution's own package is native to it, which is the
whole point:

```bash
sudo apt install -y erlang-nox erlang-dev
erl -noshell -eval 'io:format("~s~n",[erlang:system_info(otp_release)]),halt().'
```

`erlang-nox` is the runtime without wx/GUI parts; `erlang-dev` carries the headers
some deps compile NIFs against. Check what OTP major you got — it varies a lot
between releases, and it decides the Elixir version below. If it is too old for the
Elixir you want (or you need a pinned OTP), add the **Erlang Solutions** apt repo
(`packages.erlang-solutions.com`, package `esl-erlang`) — the Debian counterpart of
the RabbitMQ RPM repo used on EL.

**2) Elixir by hand into `/opt/elixir`,** from the zip **matched to that OTP major**
— `elixir-otp-27.zip` on OTP 27, `elixir-otp-26.zip` on OTP 26, and so on. Elixir is
bytecode, but an artifact compiled under a newer OTP can fail to load on an older
runtime.

```bash
sudo apt install -y unzip curl git ca-certificates
ELIXIR_VERSION=1.18.3
OTP=$(erl -noshell -eval 'io:format("~s",[erlang:system_info(otp_release)]),halt().')
curl -fsSL -o /tmp/elixir.zip \
  "https://github.com/elixir-lang/elixir/releases/download/v${ELIXIR_VERSION}/elixir-otp-${OTP}.zip"
sudo mkdir -p /opt/elixir
sudo unzip -q -o -d /opt/elixir /tmp/elixir.zip

echo 'export PATH=/opt/elixir/bin:$PATH' | sudo tee /etc/profile.d/elixir.sh
sudo chmod 0644 /etc/profile.d/elixir.sh
export PATH=/opt/elixir/bin:$PATH

mix local.hex --force && mix local.rebar --force
elixir --version
```

> Mind the floor and the ceiling: the project requires `elixir: "~> 1.15"` with no
> OTP pin, Elixir 1.15 supports OTP 24–26 and 1.18 supports OTP 25–27. If a 404 comes
> back from the URL above, that Elixir version has no build for your OTP major — pick
> the other end of the pair, not a random zip.

**3) dpkg tooling.** `dpkg-deb` is in the base system; `dpkg-shlibdeps` (which
computes the `Depends`) comes with `dpkg-dev`:

```bash
sudo apt install -y dpkg-dev
```

Without it the build still works but falls back to a hand-written dependency list
and says so — fine for a local test, not for something you ship.

### Build

```bash
mix deps.get                      # once, or let stage.sh do it
packaging/build-deb.sh            # -> packaging/dist/*.deb
```

`build-deb.sh` runs `packaging/stage.sh` (same tarball/tree as the RPM), then
assembles one `dpkg-deb --build` root per package — no debhelper and no
`dpkg-buildpackage`, because the payload is a pre-assembled release and there is
nothing to compile at package time. The deb version comes from
[`packaging/deb/changelog`](packaging/deb/changelog) and its upstream part must
match `apps/kelixip/mix.exs`, or the build stops.

Result:

```
packaging/dist/kelixip_1.1.0-1_amd64.deb                 6.9M   (release + ERTS)
packaging/dist/kelixip-mod-registrar_1.1.0-1_amd64.deb    36K
packaging/dist/kelixip-mod-auth-db_1.1.0-1_amd64.deb      24K
```

### Build in a container instead

```bash
packaging/build-in-container.sh --target ubuntu                      # ubuntu:24.04
packaging/build-in-container.sh --target ubuntu --os-version 22.04   # or any release
```

It builds [`packaging/Containerfile.ubuntu`](packaging/Containerfile.ubuntu) — apt
Erlang, the matching Elixir zip (detected from the image's OTP major, not pinned),
`dpkg-dev` — and runs `build-deb.sh` inside it. Same `packaging/dist` output as a
native run.

### Install and verify on the target

```bash
sudo apt install ./kelixip_1.1.0-1_amd64.deb ./kelixip-mod-registrar_1.1.0-1_amd64.deb
sudo systemctl enable --now kelixip
kelictl status                            # listeners bound, modules loaded
curl -s http://127.0.0.1:9095/health
```

Use `apt install ./file.deb` rather than `dpkg -i`: apt pulls the computed library
dependencies, `dpkg` only reports them missing. (Installing from a path under `$HOME`
makes apt print a warning about fetching outside its sandbox, because the `_apt` user
cannot read your home directory — harmless; copy the files to `/tmp` to silence it.)

> The package **enables** the unit but does not start it — same choice as the RPM.
> The shipped `config.toml` is a template that binds 5060 and serves no domain, so
> starting it before an admin has been through it would be a surprise, not a service.

`/etc/kelixip/config.toml`, `/etc/kelixip/domains.toml` and `/etc/default/kelixip`
are **conffiles**: on upgrade dpkg keeps your version, and (non-interactively) leaves
the packaged one next to it as `*.dpkg-dist` — the deb equivalent of `*.rpmnew`, and
worth diffing, since new keys show up there first. `apt purge` removes the state and
log directories; the `kelixip` system user is deliberately left behind.

## Development mode (no build artifact)

```bash
# run a scenario through mix (from the tool app or the umbrella root)
mix run -e "UAC.Invite.run()" apps/elixip2/scenarios/uac_invite.exs
# or via the mix task:
mix scenario apps/elixip2/scenarios/uac_invite.exs
```
